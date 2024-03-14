---
title: "Virtualbox e1000 0day Reproduce"
date: 2022-11-28
draft: false
summary: "VirtualBox E1000 Guest-to-Host Escape. But it not done yet ...."
tags: ["virtualbox"]
---

-----
mảng Tx(transmit) descriptor sẽ trông như thế này
` [context_1, data_2, data_3, context_4, data_5] `

```c
context_1.header_length = 0
context_1.maximum_segment_size = 0x3010
context_1.tcp_segmentation_enabled = true

data_2.data_length = 0x10
data_2.end_of_packet = false
data_2.tcp_segmentation_enabled = true

data_3.data_length = 0
data_3.end_of_packet = true
data_3.tcp_segmentation_enabled = true

context_4.header_length = 0
context_4.maximum_segment_size = 0xF
context_4.tcp_segmentation_enabled = true

data_5.data_length = 0x4188
data_5.end_of_packet = true
data_5.tcp_segmentation_enabled = true
``` 
### Phân tích nguyên nhân cốt lỗi gây ra bug


Các hàm quan trọng cần phải nắm 
1. `e1kXmitPending()` (src/VBox/Devices/Network/DevE1000.cpp)
```c
static int e1kXmitPending(PE1KSTATE pThis, bool fOnWorkerThread)
{
...
    while (!pThis->fLocked && e1kTxDLazyLoad(pThis))
        {
            while (e1kLocateTxPacket(pThis))
            {
                fIncomplete = false;
                /* Found a complete packet, allocate it. */
                rc = e1kXmitAllocBuf(pThis, pThis->fGSO);
                /* If we're out of bandwidth we'll come back later. */
                if (RT_FAILURE(rc))
                    goto out;
                /* Copy the packet to allocated buffer and send it. */
                rc = e1kXmitPacket(pThis, fOnWorkerThread);
                /* If we're out of bandwidth we'll come back later. */
                if (RT_FAILURE(rc))
                    goto out;
            }
        }
...
}
```
```c
DECLINLINE(bool) e1kTxDLazyLoad(PE1KSTATE pThis)
{
    if (pThis->nTxDFetched == 0)
        return e1kTxDLoadMore(pThis) != 0;
    return true;
}
```
Giả sử các descriptor ở trên được ghi vào `Tx Ring`(là nguồn từ phần cứng thông qua hệ thống cái mà được nhận vào và gửi các gói tin tới mạng). Hàm `e1kTxDLazyLoad()` sẽ được thực thi, lúc này nó sẽ đọc 5 descriptor từ Tx Ring. Tại lần đầu tiên gọi tới hàm `e1kLocateTxPacket()`, thì hàm này sẽ đi qua 1 lượt các descriptor được khởi tạo nhưng nó không handle chúng, ở lần đầu tiên thì nó chỉ đọc 3 descriptor đầu (`[context_1, data_2, data_3]`) và vòng lặp thứ 2 nó sẽ đọc 2 descriptor còn lại (`[context_4, data_5]`).

2. e1kLocateTxPacket()

```c 
static bool e1kLocateTxPacket(PE1KSTATE pThis)
{
    ...

    for (int i = pThis->iTxDCurrent; i < pThis->nTxDFetched; ++i)
    {
        E1KTXDESC *pDesc = &pThis->aTxDescriptors[i];
        switch (e1kGetDescType(pDesc))
        {
            case E1K_DTYP_CONTEXT:
                e1kUpdateTxContext(pThis, pDesc);
                continue;
            case E1K_DTYP_LEGACY:
                /* Skip empty descriptors. */
                if (!pDesc->legacy.u64BufAddr || !pDesc->legacy.cmd.u16Length)
                    break;
                cbPacket += pDesc->legacy.cmd.u16Length;
                pThis->fGSO = false;
                break;
            case E1K_DTYP_DATA:
                /* Skip empty descriptors. */
    
...
        }
    }
}
```

* Descriptor đầu tiên (`[context_1]`) nó sẽ là case `E1K_DTYP_CONTEXT` thì hàm `e1kUpdateTxContext()` sẽ được gọi và cập nhật `TCP Segmentation Context` nếu như `TCP Segmentation` được bật cho descriptor đó. 

* Descriptor thứ hai (`[data_2]`) là case `E1K_DTYP_DATA()`, nó không quan trọng trong bài viết này nên ko cần nhắc tới. 

* Descriptor thứ 3 (`[data_3]`) cũng là case `E1K_DTYP_DATA()`, nhưng mà do `data_3.data_length = 0 ` vì thế nên sẽ không có chuyện gì xảy ra 

Sau khi thực hiện xong hàm switch case thì sẽ có một hàm check liệu thuộc tính `end_of_packet` của descriptor đó có true hay không. Tại vì `data_3.end_of_packet = true` vậy nên sẽ thực thi câu lệnh bên trong hàm if và return về true. 

```c
if (pDesc->legacy.cmd.fEOP)
        {
            ...
            return true;
        }
```

Nếu như `data_3.end_of_packet` được set thành false thì 2 descriptor còn lại `[context_4, data_5]` sẽ được xử lý và lỗ hổng sẽ được bypassed. 

Bên trong vòng lặp while true của hàm `e1kXmitPending()` có gọi đến hàm `e1kXmitPacket()`, ở hàm này nó sẽ xử lý toàn bộ descriptor của chúng ta (ở đây là 5) 

```c
while (pThis->iTxDCurrent < pThis->nTxDFetched)
    {
        E1KTXDESC *pDesc = &pThis->aTxDescriptors[pThis->iTxDCurrent];
        ...
        rc = e1kXmitDesc(pThis, pDesc, e1kDescAddr(TDBAH, TDBAL, TDH), fOnWorkerThread);
        ...
        if (e1kGetDescType(pDesc) != E1K_DTYP_CONTEXT && pDesc->legacy.cmd.fEOP)
            break;
    }
```

Ứng với mỗi descriptor thì hàm `e1kXmitDesc()` sẽ được gọi để xử lý nó

```c
static int e1kXmitDesc(PE1KSTATE pThis, E1KTXDESC *pDesc, RTGCPHYS addr,
                       bool fOnWorkerThread)
{
...
    switch (e1kGetDescType(pDesc))
    {
        case E1K_DTYP_CONTEXT:
            ...
            break;
        case E1K_DTYP_DATA:
        {
            ...
            if (pDesc->data.cmd.u20DTALEN == 0 || pDesc->data.u64BufAddr == 0)
            {
                E1kLog2(("% Empty data descriptor, skipped.\n", pThis->szPrf));
            }
            else
            {
                if (e1kXmitIsGsoBuf(pThis->CTX_SUFF(pTxSg)))
                {
                    ...
                }
                else if (!pDesc->data.cmd.fTSE)
                {
                    ...
                }
                else
                {
                    STAM_COUNTER_INC(&pThis->StatTxPathFallback);
                    rc = e1kFallbackAddToFrame(pThis, pDesc, fOnWorkerThread);
                }
            }
            ...
        }
    }
}
```
Lần lượt các descriptor được đưa vào để xử lý và thực thi các hàm bên trong case tương ứng của nó

* Với descriptor đầu tiên là `context_1` thì nó sẽ không làm gì hết

* Tại vì tcp_segmentation_enable == true với tất cả các data transcriptor thì câu lệnh bên trong hàm else của câu lệnh `if (e1kXmitIsGsoBuf(pThis->CTX_SUFF(pTxSg)))` được gọi tức là hàm `e1kFallbackAddToFrame()` sẽ được thực thi, tuy nhiên ở bên trong hàm `e1kFallbackAddToFrame()` có bug `interger underflow` lúc mà data_5 được xử lý. 

```c
static int e1kFallbackAddToFrame(PE1KSTATE pThis, E1KTXDESC *pDesc, bool fOnWorkerThread)
{
    ...
    uint16_t u16MaxPktLen = pThis->contextTSE.dw3.u8HDRLEN + pThis->contextTSE.dw3.u16MSS;

    /*
     * Carve out segments.
     */
    int rc = VINF_SUCCESS;
    do
    {
        /* Calculate how many bytes we have left in this TCP segment */
        uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen;
        if (cb > pDesc->data.cmd.u20DTALEN)
        {
            /* This descriptor fits completely into current segment */
            cb = pDesc->data.cmd.u20DTALEN;
            rc = e1kFallbackAddSegment(pThis, pDesc->data.u64BufAddr, cb, pDesc->data.cmd.fEOP /*fSend*/, fOnWorkerThread);
        }
        else
        {
            ...
        }

        pDesc->data.u64BufAddr    += cb;
        pDesc->data.cmd.u20DTALEN -= cb;
    } while (pDesc->data.cmd.u20DTALEN > 0 && RT_SUCCESS(rc));

    if (pDesc->data.cmd.fEOP)
    {
        ...
        pThis->u16TxPktLen = 0;
        ...
    }

    return VINF_SUCCESS; /// @todo consider rc;
}
```

Ở hàm trên có biến `uint16_t u16MaxPktLen`, `pThis->u16TxPktLen` và `pDesc->data.cmd.u20DTALEN` là đáng để chú ý đến. 

```c
 if (e1kGetDescType(pDesc) != E1K_DTYP_CONTEXT && pDesc->legacy.cmd.fEOP)
            break;
```

Ở bên trong hàm `e1kXmitPacket()` nó có đề cập đến nếu như descriptor đang được xử lý là data và end_of_packet == true thì nó sẽ thoát khỏi vòng lặp. Transcriptor data_3 có data_3.end_of_packet == true tất yếu sẽ hủy vòng lặp trong khi còn 2 descriptor còn lại là chưa được xử lý, tại sao điều này lại quan trọng, thì tất cả các context descriptor đều được đọc sau khi đã xử lý xong data descriptor. Context descriptor được xử lý trong suốt quá trình TCP Segmentation Context Update ở trong hàm `e1kLocateTxPacket()` và data descriptor được xử lý sau đó tại bên trong vòng lặp của hàm `e1kXmitPacket()`. Người lập trình hướng theo như vậy với mục đích ngăn cản sự thay đổi giá trị của biến `u16MaxPktLen` trước khi một số data được thực thi để ngăn cản bug `interger underflow` tại hàm `e1kFallbackAddToFrame()`:

```c
uint32_t cb = u16MaxPktLen - pThis->u16TxPktLen
```

Nhưng vẫn có cách để bypass cơ chế bảo vệ này

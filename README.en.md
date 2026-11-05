[Русский](README.md) | [English](README.en.md)

# Can delaying a TCP ACK make the TSPU forget a TCP session?

**There is one way to find out.**

According to [tspu-docs](https://github.com/DanielLavrushin/tspu-docs), the TSPU retains session state for a limited time. The hypothesis was that delaying part of the TCP three-way handshake might cause the TSPU to forget the session before the connection endpoints do.

`youtube.com` was selected as the test case.

Initial experiments using **Wireshark** and **Scapy** produced results consistent with this hypothesis: after a delay, the connection continued even though, judging by the observed traffic, the TSPU no longer tracked its state.

I later implemented the experiment in a **Python** script using **WinDivert** to intercept packets. This became `bypass.py`.

## Requirements

1. **Windows**
2. Install pydivert `pip install pydivert`
3. Replace `ip = "YOUR_LOCAL_ADDR"` with your computer’s local address.
4. Run the script from a terminal **as an administrator** `python bypass.py`
5. Open a browser, navigate to **youtube.com**, and wait.

## Results

Depending on the outcome, the script may print:

`TLS Server Hello detected, TLS handshake bypassed`

If this message appears, a 15-second delay was sufficient for the connection to continue in the tested network. This is consistent with the TSPU having expired its session state. If the message does not appear, you can try increasing the delay.

Close the browser before each test so that existing connections to **youtube.com** do not affect the result.

### Why this result matters

The experiment demonstrates a timing difference between how long the TSPU tracks a connection and how long the endpoints continue to treat it as active. In the tested network, delaying an ACK allowed the connection to continue after the TSPU had likely stopped tracking the session. This is an important observation because it shows how a timeout in a network filtering system can create an opportunity for a TCP connection to proceed.

## Limitations

- The script supports **IPv4**. **IPv6**, **UDP**, and **QUIC** are not supported.
- The delay is set with `DELAY`. The suitable value and the outcome depend on the TSPU in your network.
- While running, the script intercepts, delays, and drops some packets involving addresses that your DNS resolves for **youtube.com**. It is experimental and may slow down or interrupt connections.

## This is a research experiment, not a universal tool for bypassing internet restrictions.

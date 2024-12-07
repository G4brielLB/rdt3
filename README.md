# Reliable Data Transfer (RDT) 3.0 Protocol

This project implements the Reliable Data Transfer (RDT) 3.0 protocol as described by Kurose and Ross in their book "Computer Networking: A Top-Down Approach". The implementation is divided into two main components: `host.py` and `router.py`.

## Files

### `host.py`
This file contains the implementation of the host component of the RDT 3.0 protocol. The host is responsible for sending and receiving data packets, ensuring reliable communication over an unreliable network.

### `router.py`
This file contains the implementation of the router component of the RDT 3.0 protocol. The router simulates the network layer, forwarding packets between hosts and potentially introducing packet loss or corruption to test the reliability of the protocol.

## Usage

To run the implementation, you need to execute both the `host.py` and `router.py` scripts. Ensure that you have Python installed on your system.

1. Start the router:
    ```sh
    python router.py
    ```

2. Start the host:
    ```sh
    python host.py
    ```

## Requirements

- Python 3.x

## References

- Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach (7th ed.). Pearson.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

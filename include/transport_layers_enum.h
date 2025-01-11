#pragma once


namespace flow_inspector {


enum class TransportLayerProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unknown
};


}
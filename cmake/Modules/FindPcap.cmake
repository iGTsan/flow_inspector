find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    set(PCAP_FOUND TRUE)
else()
    set(PCAP_FOUND FALSE)
endif()

if(PCAP_FOUND)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    message(STATUS "Found PCAP: ${PCAP_LIBRARIES}")
else()
    message(STATUS "Could not find PCAP")
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)

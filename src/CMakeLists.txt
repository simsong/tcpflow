set(CMAKE_CXX_STANDARD 11)

# System Dependencies
find_package(Boost) #TODO(olibre): COMPONENTS program_options system)
find_package(PCAP)
find_package(OpenSSL)
find_package(Threads)
find_package(PythonLibs)


# TODO(olibre): Use target_link_libraries() instead of include_directories()
include_directories(.)


# TODO(olibre): Fix detection of below headers
include (CheckIncludeFiles)
# Below lines have been produced using this command line
# sed 's|/\* ||' config.h | awk '$1 ~ /#undef|#define/{print $2}' | sort -u | while read w ; do grep -wB1 $w config.h | grep '[^ ]*> header' | sed "s/.*</check_include_files(/;s/>//;s/header.*/$w)/"; done
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(boost/icl/interval.hpp HAVE_BOOST_ICL_INTERVAL_HPP)
check_include_files(boost/icl/interval_map.hpp HAVE_BOOST_ICL_INTERVAL_MAP_HPP)
check_include_files(boost/icl/interval_set.hpp HAVE_BOOST_ICL_INTERVAL_SET_HPP)
check_include_files(boost/version.hpp HAVE_BOOST_VERSION_HPP)
check_include_files(cairo/cairo.h HAVE_CAIRO_CAIRO_H)
check_include_files(cairo/cairo-pdf.h HAVE_CAIRO_CAIRO_PDF_H)
check_include_files(cairo.h HAVE_CAIRO_H)
check_include_files(cairo-pdf.h HAVE_CAIRO_PDF_H)
check_include_files(ctype.h HAVE_CTYPE_H)
check_include_files(err.h HAVE_ERR_H)
check_include_files(exiv2/image.hpp HAVE_EXIV2_IMAGE_HPP)
check_include_files(expat.h HAVE_EXPAT_H)
check_include_files(fcntl.h HAVE_FCNTL_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(linux/if_ether.h HAVE_LINUX_IF_ETHER_H)
check_include_files(memory.h HAVE_MEMORY_H)
check_include_files(net/ethernet.h HAVE_NET_ETHERNET_H)
check_include_files(net/if.h HAVE_NET_IF_H)
check_include_files(net/if_var.h HAVE_NET_IF_VAR_H)
check_include_files(netinet/in.h HAVE_NETINET_IN_H)
check_include_files(netinet/in_systm.h HAVE_NETINET_IN_SYSTM_H)
check_include_files(netinet/ip_ether.h HAVE_NETINET_IP_ETHER_H)
check_include_files(netinet/ip.h HAVE_NETINET_IP_H)
check_include_files(netinet/ip_var.h HAVE_NETINET_IP_VAR_H)
check_include_files(netinet/tcp.h HAVE_NETINET_TCP_H)
check_include_files(netinet/tcpip.h HAVE_NETINET_TCPIP_H)
check_include_files(openssl/aes.h HAVE_OPENSSL_AES_H)
check_include_files(openssl/bio.h HAVE_OPENSSL_BIO_H)
check_include_files(openssl/evp.h HAVE_OPENSSL_EVP_H)
check_include_files(openssl/hmac.h HAVE_OPENSSL_HMAC_H)
check_include_files(openssl/md5.h HAVE_OPENSSL_MD5_H)
check_include_files(openssl/pem.h HAVE_OPENSSL_PEM_H)
check_include_files(openssl/rand.h HAVE_OPENSSL_RAND_H)
check_include_files(openssl/rsa.h HAVE_OPENSSL_RSA_H)
check_include_files(openssl/sha.h HAVE_OPENSSL_SHA_H)
check_include_files(openssl/x509.h HAVE_OPENSSL_X509_H)
check_include_files(pcap.h HAVE_PCAP_H)
check_include_files(pcap/pcap.h HAVE_PCAP_PCAP_H)
check_include_files(pthread.h HAVE_PTHREAD_H)
check_include_files(pwd.h HAVE_PWD_H)
check_include_files(regex.h HAVE_REGEX_H)
check_include_files(semaphore.h HAVE_SEMAPHORE_H)
check_include_files(signal.h HAVE_SIGNAL_H)
check_include_files(sqlite3.h HAVE_SQLITE3_H)
check_include_files(stdint.h HAVE_STDINT_H)
check_include_files(stdio.h HAVE_STDIO_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string HAVE_STRING)
check_include_files(string.h HAVE_STRING_H)
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(sys/bitypes.h HAVE_SYS_BITYPES_H)
check_include_files(sys/cdefs.h HAVE_SYS_CDEFS_H)
check_include_files(syslog.h HAVE_SYSLOG_H)
check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
check_include_files(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(sys/types.h HAVE_SYS_TYPES_H)
check_include_files(sys/utsname.h HAVE_SYS_UTSNAME_H)
check_include_files(sys/wait.h HAVE_SYS_WAIT_H)
check_include_files(tr1/unordered_map HAVE_TR1_UNORDERED_MAP)
check_include_files(tr1/unordered_set HAVE_TR1_UNORDERED_SET)
check_include_files(tre/tre.h HAVE_TRE_TRE_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(unordered_map HAVE_UNORDERED_MAP)
check_include_files(unordered_set HAVE_UNORDERED_SET)
check_include_files(winsock2.h HAVE_WINSOCK2_H)
check_include_files(zlib.h HAVE_ZLIB_H)
check_include_files(python2.7/Python.h PYTHON2_7_PYTHON_H)  # TODO(olibre): Use instead PYTHON_INCLUDE_DIRS
# There are many other #define not (yet) implemented by above CMake directives.
# To list the #define use the following command lines:
# sed 's|/\* ||' config.h | awk '$1 ~ /#undef|#define/{print $2}' | sort -u | while read w ; do grep -wB1 $w config.h | grep '[^ ]*> header' -q && echo $w; done > already-implemented-using-cmake-directives
# ( sed 's|/\* ||' config.h | awk '$1 ~ /#undef|#define/{print $2}'  | sort -u | while read w ; do find src -name 'config.h' -o -regex '.*.h\|.*.cpp' -exec fgrep -Iowqm1 $w {} '+' && echo "$w" ; done ) > used-in-source-code
# comm -13 already-implemented-using-cmake-directives used-in-source-code | grep -wf - config.h -B1 --color=always > rest-to-implement-using-cmake-directives
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# When all #define from config.h are implemented using CMake directives the following line...
include_directories(..)                            #include the <config.h> generated by autotools
# ...by this one:
# include_directories(${CMAKE_CURRENT_BINARY_DIR}) #include the <config.h> generated by CMake



file (GLOB netviz_cpp netviz/*.cpp)
file (GLOB netviz_h   netviz/*.h)
source_group("netviz headers" FILES ${netviz_h})
add_library (netviz  ${netviz_cpp}  ${netviz_h})
target_link_libraries(netviz cairo)  # TODO(olibre): Only if libcairo is present
target_include_directories(netviz PUBLIC netviz)
target_link_libraries(netviz cairo)

# add_subdirectory(dfxml/src)
set(dfxml_writer_h dfxml/src/dfxml_writer.h dfxml/src/hash_t.h)
source_group("dfxml_writer headers" FILES ${dfxml_writer_h})
add_library (dfxml_writer dfxml/src/dfxml_writer.cpp ${dfxml_writer_h})
target_link_libraries(dfxml_writer OpenSSL::SSL)
target_include_directories(dfxml_writer PUBLIC dfxml/src)

#file (GLOB wifipcap_glob_cpp wifipcap/*.cpp)
#file (GLOB wifipcap_glob_h   wifipcap/*.h)
#set (wifipcap_cpp datalink_wifi.cpp ${wifipcap_glob_cpp} )
#set (wifipcap_h   datalink_wifi.h   ${wifipcap_glob_h} )
set (wifipcap_cpp
    datalink_wifi.cpp
    scan_wifiviz.cpp
    wifipcap/TimeVal.cpp
    wifipcap/cpack.cpp
    wifipcap/wifipcap.cpp
    )
set (wifipcap_h
    datalink_wifi.h
    wifipcap/TimeVal.h
    wifipcap/arp.h
    wifipcap/cpack.h
    wifipcap/ether.h
    wifipcap/ethertype.h
    wifipcap/extract.h
    wifipcap/icmp.h
    wifipcap/ieee802_11_radio.h
    wifipcap/ip.h
    wifipcap/ip6.h
    wifipcap/ipproto.h
    wifipcap/llc.h
    wifipcap/os.h
    wifipcap/oui.h
    wifipcap/prism.h
    wifipcap/radiotap.h
    wifipcap/tcp.h
    wifipcap/types.h
    wifipcap/udp.h
    wifipcap/util.h
    wifipcap/wifipcap.h
    )
source_group("wifipcap headers" FILES ${wifipcap_h})
add_library (wifipcap ${wifipcap_cpp} ${wifipcap_h})
target_link_libraries(wifipcap dfxml_writer)
target_include_directories(wifipcap PUBLIC wifipcap be13_api pcap)  # TODO(olibre): Should not depend on be13_api

# add_subdirectory(http-parser)
source_group("http-parser headers" FILES http-parser/http_parser.h)
add_library (http-parser
    http-parser/http_parser.h
    http-parser/http_parser.c
)

# add_subdirectory(be13_api)
file (GLOB_RECURSE be13_api_h   be13_api/*.h)
file (GLOB         be13_api_cpp be13_api/*.cpp)
source_group("be13_api headers" FILES ${be13_api_h})
add_library (be13_api ${be13_api_h} ${be13_api_cpp})
target_link_libraries(be13_api wifipcap)
target_include_directories(be13_api PUBLIC be13_api)

set (tcpflow_cpp datalink.cpp flow.cpp
    tcpflow.cpp
    tcpip.cpp
    tcpdemux.cpp
    util.cpp
    scan_md5.cpp
    scan_http.cpp       # Depends on zlib
    scan_tcpdemux.cpp
    scan_netviz.cpp
    pcap_writer.h
    mime_map.cpp
)

# removed because it hasn't been updated to Python 3:
# scan_python.cpp     # Depends on PYTHON_LIBRARIES


set (tcpflow_h
    iptree.h
    mime_map.h
    tcpip.h
    intrusive_list.h
    tcpflow.h
    tcpdemux.h
)
source_group("tcpflow headers" FILES ${tcpflow_h})
add_executable(tcpflow ${tcpflow_cpp} ${tcpflow_h})
target_link_libraries(tcpflow netviz wifipcap be13_api dfxml_writer http-parser z pcap ${PYTHON_LIBRARIES})  # add also ${PYTHON_INCLUDE_PATH}

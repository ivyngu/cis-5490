In this project, I wrote code to analyze a pcap file for a TCP session. To do so, I had to analyze pcap files in Wireshark, and figure out the format of a pcap file in order to decode it. 
My code handles the fact that TCP sessions could be happening in parallel or simultaneously. 

In order to run the code, one has to type on the command line: ./pcap-analysis tcp-analysis [pcap file to analyze .pcap] [file to store session data .txt]

By running this code,  records each session's server IP & port, client IP & port, the number of packets sent, the total IP traffic bytes sent, the total user traffic bytes sent, the session duration, throughput, and goodput.

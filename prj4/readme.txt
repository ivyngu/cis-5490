In this project, my partner and I designed and implemented a downlink traffic aggregation mechanism at the IP layer to utilize both the LTE and Wi-Fi networks simultaneously. 
Our idea was to vary sending packets along the Wi-Fi or LTE path by calculating scores for each path. To determine these two scores, we considered the delay along each path from router to UE and the throughput of each path in real time. 
If the delay was low and throughput was high for a certain path, we were more likely to choose that path. Otherwise, we prioritized lower delays over higher throughputs when calculating our scores (i.e. if a path had a lower delay time but also
high throughput, we would choose it over the path with higher delay time). We also resorted to Wi-Fi as the default path in the case where LTE and Wi-Fi conditions were similar.
While our algorithm worked somewhat decently, there were several things we could improve upon to make it even more efficient, such as considering the traffic input bit rate measurement at the router toward LTE and Wi-Fi paths.

Alongside this algorithm, we also had to implement in-packet ordering at the receiver side (the UE) that receives traffic from multiple networks (LTE & Wi-Fi). We validated this mechanism using several different scenarios: for example, having a lost packet. 

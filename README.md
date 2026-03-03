# Parallel-DPI-Engine

## Getting things to work 
how to get things to work on the user's own machine and showing an example of how it looks on mine (gif). 
Show the user how to send signals and check debug log and also change all the text files for experimentation. 

## Project Overview 
Stateful DPI Engine designed for high throughput. Leverages Linux-native zero copy primatives and DFA (Aho-Corasick's Algo)
for recognising patterns. How fast can this run???? 

## What is Aho-Corasick's Algo 
Talk about the basics of the DFA and what its purpose is. 

## Data Plane and Ingress 
- Driver: AF_PACKET with PACKET_MMAP to allow for Zero-Copy 
- Kernel User Interface: Circular ring buffer via mmap(), eliminating extra uses of expensive memcpy and recv calls.
- Load Balancing: PACKET_FANOUT_HASH at the kernel level to ensure low affinity, ie. packets from the same TCP stream always go to the same worker. Notice that this solves only spacial locality issues regarding the same TCP 5-tuple being delivered to the correct worker thread but does't solve temporal locality issues. E.g: say that TCH arrives before MA but the true order is supposed to be MA then TCH, this would not be 
detected. To solve in the future, create a buffer for each worker that reorganises the 'bundle' of packets taken from the kernel with respect to time sent. Though this does slow the system down, it ensures that nothing is being missed. 

## L7 Protocol Identification 
The engine performs protocol fingerprinting by inspecting the first 8-16 bytes of every TCP payload to detect HTTP or TLS or else... 

## State Saving 
Using hash values to map worker states to a flow table to ensure that every TCP that shares the same 5-tuple will be able to continue through the algo loop without external interference. Safety system: flow aging (30s) and flow nuking (60s) 

## TUI 
Talk about how metrics are captures directly in the sniffer and then those metrics are displayed directly in the TUI to see. 



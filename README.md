## Netfloc exporter for Prometheus

This is exporter for [Netfloc - the SDK for SDN](https://github.com/icclab/netfloc). Shows metrics from Netfloc monitoring module that are exposed via the OpenFlow plugin statistics Collector APIs from OpenDaylight. 
The exporter bases on the example of the [Jenkins exporters]
(https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
https://github.com/lovoo/jenkins_exporter).

### Installation

```
git clone git@github.com:icclab/netfloc-prometheus-exporter
```


### Usage

```
netfloc-prometheus-exporter.py [-h] [-n netfloc] [-i netfloc_inventory]
                                      [-p port]

Netfloc exporter args - netfloc address, inventory and port

optional arguments:
  -h, --help            show this help message and exit
  -n netfloc, --netfloc netfloc
                        Netfloc url
  -i netfloc_inventory, --netfloc_inventory netfloc_inventory
                        Netfloc inventory url
  -p port, --port port  Exporter listens to this port
```




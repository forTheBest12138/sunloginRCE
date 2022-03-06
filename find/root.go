package find

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

type iplist struct {
	ip   string
	port int
}

func cidrHosts(netw string) ([]string, error) {
	// make a slice to return host addresses
	var hosts []string
	if strings.ContainsAny(netw, "/") == false {
		hosts = append(hosts, netw)
		return hosts, nil
	}
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(netw)
	if err != nil {
		return nil, err
	}
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	// find the start IP address
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final IP address
	finish := (start & mask) | (mask ^ 0xffffffff)
	// loop through addresses as uint32.
	// I used "start + 1" and "finish - 1" to discard the network and broadcast addresses.
	for i := start + 1; i <= finish-1; i++ {
		// convert back to net.IPs
		// Create IP address of type net.IP. IPv4 is 4 bytes, IPv6 is 16 bytes.
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// return a slice of strings containing IP addresses
	return hosts, nil
}

func RootScan(ip string, port string, x int) {

	portsChan := make(chan iplist, x)
	var results []iplist

	jobDoneWaiter := sync.WaitGroup{}
	jobDoneWaiter.Add(x)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		printResults(results)
		os.Exit(0)
	}()

	//解析扫描端口范围
	portsToScan, err := parsePortsToScan(port)
	if err != nil {
		fmt.Printf("Failed to parse ports to scan: %s\n", err)
		os.Exit(1)
	}

	//解析ip段
	ipList, err := cidrHosts(ip)
	if err != nil {
		fmt.Println("Failed to parse ip to scan: %v\n", err)
		os.Exit(1)
	}

	//这里可直接使用参数x代替cap(protsChan),因为channel的缓冲区长度在初始化后就不变了
	//for i := 0; i < cap(portsChan); i++ { // numWorkers also acceptable here
	for i := 0; i < x; i++ { // numWorkers also acceptable here
		go worker(portsChan, &results, &jobDoneWaiter)
	}

	go func() {
		for _, ip := range ipList {
			for _, port := range portsToScan {
				tmp := iplist{ip, port}
				portsChan <- tmp
			}
		}
		close(portsChan)
	}()

	//for i := 0; i < len(portsToScan); i++ {
	//	if p := <-resultsChan; p != 0 { // non-zero port means it's open
	//		openPorts = append(openPorts, p)
	//	}
	//}

	jobDoneWaiter.Wait()
	printResults(results)
}

package find

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"xrkRce/config"
	"xrkRce/rce"
)

func parsePortsToScan(portsFlag string) ([]int, error) {
	p, err := strconv.Atoi(portsFlag)
	if err == nil {
		return []int{p}, nil
	}

	ports := strings.Split(portsFlag, "-")
	if len(ports) != 2 {
		return nil, errors.New("unable to determine port(s) to scan")
	}

	minPort, err := strconv.Atoi(ports[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to a valid port number", ports[0])
	}

	maxPort, err := strconv.Atoi(ports[1])
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to a valid port number", ports[1])
	}

	if minPort <= 0 || maxPort <= 0 {
		return nil, fmt.Errorf("port numbers must be greater than 0")
	}

	var results []int
	for p := minPort; p <= maxPort; p++ {
		results = append(results, p)
	}
	return results, nil
}

func worker(portsChan <-chan iplist, results *[]iplist, jobDoneWaiter *sync.WaitGroup) {
	defer jobDoneWaiter.Done()

	for target := range portsChan {
		address := fmt.Sprintf("%s:%d", target.ip, target.port)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			//fmt.Printf("%d CLOSED (%s)\n", p, err)
			continue
		}
		conn.Close()
		*results = append(*results, target)
	}
}

func printResults(results []iplist) {
	//fmt.Println("\nResults\n--------------")
	fmt.Println(results)
	for _, result := range results {
		//fmt.Println("%d - open\n", p)
		config.SetIp(result.ip)
		pp := strconv.Itoa(result.port)
		rce.GetWebInfo(pp)
	}
}

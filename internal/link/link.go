// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package link

import (
	"log/slog"
	"net"
	"os"

	netlink "github.com/vishvananda/netlink"
	nl "github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type Error string

func (e Error) Error() string {
	return string(e)
}

const NoDefaultRouteError = Error("default route does not exist")

// Detects and returns IPv4 source address for local node via default route
func GetLocalSrcIP() (ip net.IP, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Incorrect link name or default route is absent", slog.Any("error", r))
			os.Exit(1)
		}
	}()

	_, defaultGWNet, _ := net.ParseCIDR("0.0.0.0/0")

	routeList, err := netlink.RouteListFiltered(nl.FAMILY_V4, &netlink.Route{
		Dst:   defaultGWNet,
		Table: unix.RT_TABLE_MAIN,
	}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		slog.Error("unable to autodetect link device", slog.Any("error", err))
		os.Exit(1)
	}

	if len(routeList) < 1 {
		return nil, NoDefaultRouteError
	}

	if routeList[0].Src != nil {
		//slog.Info(fmt.Sprintf("Successfully autodetected egress IP: %v", routeList[0].Src))

		// Early exit if SRC IP is defined in default route
		return routeList[0].Src, nil
	}

	// As Src IP is not defined for last resort route - trying to get first IP of related interface
	link, err := netlink.LinkByIndex(routeList[0].LinkIndex)
	if err != nil {
		panic(err)
	}

	addressList, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		panic(err) //TODO: NOPANIC!
	}

	if len(addressList) < 1 {
		return nil, NoDefaultRouteError
	}

	//slog.Debug("received routelist content", slog.Any("routelist", routeList)) // TODO: smth

	return addressList[0].IP, nil
}

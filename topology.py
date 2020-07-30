#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 15 00:17:44 2020

@author: mvr
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller,RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel,info
from mininet.util import dumpNodeConnections
from mininet.link import Link,Intf,TCLink
import os
from time import sleep
import sys
class Topology(Topo):
    def __init__(self):
	Topo.__init__(self)
	Host1 = self.addHost( 'h1' )
	Host2 = self.addHost( 'h2' )
	Host3 = self.addHost( 'h3' )
	Host4 = self.addHost( 'h4' )
	A = self.addSwitch( 's1' )
	B = self.addSwitch( 's2' )
	C = self.addSwitch( 's3' )
	D = self.addSwitch( 's4' )
	
	self.addLink( Host1, A, 1, 1 )
	self.addLink( Host2,B, 1, 1 )
	self.addLink( Host3,C, 1, 1 )
	self.addLink( Host4,D, 1, 1)
	self.addLink( A,B, 2 , 2 )
	self.addLink( A,D, 3, 2 )
	self.addLink( B,C, 3, 2 )
	self.addLink( C,D, 3, 3 )
topos={'mytopo':(lambda:Topology())}
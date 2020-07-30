#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 15 00:14:18 2020

@author: mvr
"""

from mininet.topo import Topo
class FatTree( Topo ):
    CoreSwitchList = []
    EdgeSwitchList = []
    HostList = []
    def __init__( self, n):
        self.CoreLayerSwitch = n/2

        self.EdgeLayerSwitch = n
        self.density = n/2
        self.Host =  n*n/2

        Topo.__init__(self)

        self.createTopo()

        self.createLink()

    def createTopo(self):
        self.createCoreLayerSwitch(self.CoreLayerSwitch)
        self.createEdgeLayerSwitch(self.EdgeLayerSwitch)
        self.createHost(self.Host)


    def createHost(self, number):
        for xy in range(1, number+1):

            self.HostList.append(self.addHost(str("H") + str(xy)))
    def createCoreLayerSwitch(self, number):

        self._addSwitch(number, 2, self.CoreSwitchList)

    def _addSwitch(self, number, level, switch_list):
        for xx in range(1, number+1):
            switch_list.append(self.addSwitch('s' + str(level) + str(xx)))



    def createEdgeLayerSwitch(self, number):

        self._addSwitch(number, 1, self.EdgeSwitchList)


    def createLink(self):
        for xz in range(0,self.EdgeLayerSwitch):
            for ia in range(0,self.CoreLayerSwitch):
                self.addLink(self.EdgeSwitchList[xz],self.CoreSwitchList[ia])


        for xa in range(0, self.EdgeLayerSwitch):
            for ib in range(0, self.density):
                self.addLink(self.EdgeSwitchList[x],self.HostList[self.density * xa + ib])

topos = { 'fattree' : ( lambda n : FatTree(n)) }
#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2020 FABRIC Testbed
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Author: Tristan Jordan

import os
import traceback
import re

import functools

import importlib.resources as pkg_resources
from typing import List

from fabrictestbed.slice_editor import ExperimentTopology, Capacities, ComponentType, ComponentModelType, ServiceType, ComponentCatalog
from fabrictestbed.slice_editor import (
    ExperimentTopology,
    Capacities
)
from fabrictestbed.slice_manager import SliceManager, Status, SliceState

import ipycytoscape as cy
from IPython.display import display
from ipywidgets import Output

from abc_topology_editor import AbcTopologyEditor


class GraphTopologyEditor(AbcTopologyEditor):
    # FABRIC design elements https://fabric-testbed.net/branding/style/
    FABRIC_PRIMARY = '#27aae1'
    FABRIC_PRIMARY_LIGHT = '#cde4ef'
    FABRIC_PRIMARY_DARK = '#078ac1'
    FABRIC_SECONDARY = '#f26522'
    FABRIC_SECONDARY_LIGHT = '#ff8542'
    FABRIC_SECONDARY_DARK = '#d24502'
    FABRIC_BLACK = '#231f20'
    FABRIC_DARK = '#433f40'
    FABRIC_GREY = '#666677'
    FABRIC_LIGHT = '#f3f3f9'
    FABRIC_WHITE = '#ffffff'
    def select_node(self,node):
        """
        Selects node within graph
        :return:
        """
        node["selected"]=True
        self.selected=node
        self.load_vm(node)

    
    def addNode(self,b):
        """
        Adds a basic node to the graph
        :return:
        """
        new_node = cy.Node()
        new_node.data["id"] = self.nodecount
        self.nodecount+=1
        new_node.data["name"] = "NewVM"
        new_node.data["site"] = "UKY"
        new_node.data["core_count"] = "4"
        new_node.data["ram_count"] = "64"
        new_node.data["disk_count"] = "500"
        new_node.data["image_type"] = "qcow2"
        new_node.data["image_reference"] = "default_centos_8"
        new_node.selectable=True
        self.Canvas.graph.add_node(new_node)
        
    def save_vm(self,change):
        """
        Saves VM state into selected VM
        :return:
        """
        if(self.selected is not None):
            for node in self.Canvas.graph.nodes:
                if node.data["id"] == int(self.selected["data"]["id"]):
                    node.data["name"] = self.vm_name.value
                    node.data["site"] = self.site.value
                    node.data["core_count"] = self.core_count.value
                    node.data["ram_count"] = self.ram_count.value
                    node.data["disk_count"] = self.disk_count.value
                    node.data["image_type"] = self.image_type.value
                    node.data["image_reference"] = self.image_reference.value
    
    def load_vm(self,change):
        if(self.selected is not None):
            vm = self.selected["data"]
            self.vm_name.value = vm["name"]
            self.site.value = vm["site"]
            self.core_count.value = vm["core_count"]
            self.ram_count.value = vm["ram_count"]
            self.disk_count.value = vm["disk_count"]
            self.image_type.value = vm["image_type"]
            self.image_reference.value = vm["image_reference"]

    def __init__(self, width=100, height =100, BG ='#584f4e'):
        """
        Constructor
        :return:
        """
        super().__init__()

        self.out = Output()
        
        
        
    def canvas_init(self):
        """
        Initialize canvas
        :return:
        """
        data = {
            'nodes': [
                
            ],
            'edges': [
                
            ]
        }
        self.Canvas = cy.CytoscapeWidget()
        self.style = [
                        {'selector': 'node','style':
                            {
                                'content': 'data(name)',
                                'text-valign': 'center',
                                'color': 'white',
                                'text-outline-width': 2,
                                'text-outline-color': self.FABRIC_PRIMARY,
                                'background-color': self.FABRIC_PRIMARY
                            }
                        },
                        {'selector': 'node[id = 0]','style':
                            {
                                'background-color': 'black',
                                'line-color': 'black',
                                'target-arrow-color': 'black',
                                'source-arrow-color': 'black',
                                'text-outline-color': 'black'
                            }
                        }
                        
                        ]
        self.Canvas.set_style(self.style)
        self.Canvas.graph.add_graph_from_json(data)
        self.Canvas.on('node', 'click', self.select_node)
        
        
        self.Menu = widgets.Box(layout=widgets.Layout(display="flex", flex_flow="column", align_items="stretch"))
        
        self.addNodeButton= widgets.Button(description="Add VM")
        self.addNodeButton.on_click(self.addNode)
        
        self.vm_name =  widgets.Text(value="VM",description='VM Name:',disabled=False)
        self.site = widgets.Dropdown(options=['UKY', 'RENC', 'LBNL', 'STAR'],value='UKY',description='Site:',disabled=False,)
        self.core_count = widgets.Text(value="4",description='Core:',disabled=False)
        self.ram_count = widgets.Text(value="64",description='Ram:',disabled=False)
        self.disk_count = widgets.Text(value="500",description='Disk:',disabled=False)
        self.image_type =widgets.Dropdown(options=['qcow2'],value='qcow2',description='Image Type:',disabled=False,)
        self.image_reference = widgets.Dropdown(options=['default_centos_8'],value='default_centos_8',description='Image Reference',disabled=False,)
        
        self.vm_controls = [self.vm_name,self.site,self.core_count,self.ram_count,self.disk_count,self.image_type,self.image_reference]
        for control in self.vm_controls:
            control.observe(self.save_vm)
            
        self.Menu.children = [self.addNodeButton,self.vm_name,self.site,self.core_count,self.ram_count,self.disk_count,self.image_type,self.image_reference]
        self.AL=AppLayout(right_sidebar=self.Menu,
          center=self.Canvas)
        display(self.AL)
        
    def start(self):
        """
        Start the graph editor
        :return:
        """
        self.nodecount=0
        self.selected = None
        self.canvas_init()
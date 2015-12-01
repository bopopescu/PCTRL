
# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
Turns your complex OpenFlow switches into stupid hubs.
"""

from pox.core import core
import pox.openflow.libpof_02 as of
from pox.lib.util import dpidToStr
from time import sleep
log = core.getLogger()


#######################################################################
#setup USTC/NC/IOA flow table when tests cooperation_loop
#######################################################################
def cooper_loop_ustc(event):    
  ofmatch20_1 =of.ofp_match20()
  ofmatch20_1.fieldId=0
  ofmatch20_1.offset=0
  ofmatch20_1.length=48
  
  ofmatch20_2 =of.ofp_match20()
  ofmatch20_2.fieldId=-1
  ofmatch20_2.offset=272
  ofmatch20_2.length=32
  
  ofmatch20_3 =of.ofp_match20()
  ofmatch20_3.fieldId= -1
  ofmatch20_3.offset= 336
  ofmatch20_3.length= 16
  
  ofmatch20_4 =of.ofp_match20()
  ofmatch20_4.fieldId= -1
  ofmatch20_4.offset= 160
  ofmatch20_4.length= 16
  
  ofmatch20_5 =of.ofp_match20()
  ofmatch20_5.fieldId= 2
  ofmatch20_5.offset= 96
  ofmatch20_5.length=16
  
  ofmatch20_6 =of.ofp_match20()
  ofmatch20_6.fieldId=7
  ofmatch20_6.offset=184
  ofmatch20_6.length=8
  
  ofmatch20_7 =of.ofp_match20()
  ofmatch20_7.fieldId= 12
  ofmatch20_7.offset= 288
  ofmatch20_7.length=16
  
  ##############################################################################
  #table_mod 0   MM
  ###############################################################################
  
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_1)
  #msg.flowTable.matchFieldList.append(ofmatch20_3)
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType=0  #OF_MM_TABLE
  msg.flowTable.matchFieldNum = 1
  msg.flowTable.tableSize=128
  msg.flowTable.tableId=0
  msg.flowTable.tableName="FirstEntryTable"
  msg.flowTable.keyLength=48
  event.connection.send(msg)

  ##############################################################################
  #table_mod 16  MacMap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="MacMap"
  event.connection.send(msg)
  
  
  ##############################################################################
  #table_mod 17  VNI
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VNI"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 18  VxLanEncap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanEncap"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 8  FIB
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_2)
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 1
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 32
  msg.flowTable.tableName="FIB"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 21  FIB_DT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=5
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="FIB_DT"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 19  EPAT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=3
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="EPAT"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 1 L2PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_5)
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 16
  msg.flowTable.tableName="L2PA"
  event.connection.send(msg)
  
  
   ##############################################################################
  #table_mod 2  L3PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_6)
  msg.flowTable.matchFieldList.append(ofmatch20_7)
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 24
  msg.flowTable.tableName="L3PA"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 20 VxLanDecap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=4
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanDecap"
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-0  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 0
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("90e2ba2a22ca")  #Network Center PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0      
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-1  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 1
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("6cf0498cd47b")  #SXS PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1   #because
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-2  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 2
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("000000000003")  #'/
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 16
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
    ##############################################################################
  #flow_mod 0-3  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 3
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("bc305ba4e124")  #USTC PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-4  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 4
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("643e8c394002")  #USTC Switch MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-5  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 5
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("ffffffffffff")  #for ARP request
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 16-0  MacMap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_setfield()
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= 1
  tempmatchx.offset= 0
  tempmatchx.length= 48
  tempmatchx.set_value("bc305ba4e124")
  action.fieldSetting = tempmatchx
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-0  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('72d6a6c1')  #USTC Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('9FE23D4B')    #Network Center Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-1  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('72d6a6c1')  #USTC Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('D24BE144')    #SXS Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-0  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=128
  tempins.set_value('0800') #EthType
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=144
  tempins.set_value('4500')  #V_IHL_TOS
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=208
  tempins.set_value('4011')  #TTL  & Protocol
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=320
  tempins.set_value('12b5')  #UDP Dport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-1  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 4
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=368
  tempins.set_value('80')  #VxLan Flag
  tempins.writeLength = 8
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket()  #Total length to UDP_length
  tempins.metadataOffset= 336
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket() #Total length to  Total length 
  tempins.metadataOffset= 160
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 2
  msg.instruction.append(tempins)
  event.connection.send(msg)

  ##############################################################################
  #flow_mod 18-2  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 5
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 2
  
  tempins=of.ofp_instruction_calculatefiled()  #UDP_length + 30
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_3
  tempins.src_value = 30
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_calculatefiled()#Total_length + 50
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_4
  tempins.src_value = 50
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 3
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-3  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 3
  
  
  tempins=of.ofp_instruction_writemetadata() 
  tempins.metaDataOffset=304
  tempins.set_value('04d2') #UDP Sport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 4
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-4  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 7
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 4
  
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_calculatechecksum()
  action.checksumPosType = 1
  action.calcPosType = 1
  action.checksumPosition = 224
  action.checksumLength = 16
  action.calcStarPosition = 144
  action.calcLength = 160
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 8
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_2])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 8-0 FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("9FE23D4B") #Network Center switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 8-1  FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("D24BE144") #SXS switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 21-0  FIB_DT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 9
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 5
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=32
  tempins.set_value('001244662000')   #USTC GateWay MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-0  EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=80
  tempins.set_value('643e8c394002')   #USTC switch MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x10041
  action.metadataOffset=32
  action.metadataLength=400
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-1   EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x10043
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-0   L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0800")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 2
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_6,ofmatch20_7])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-1 L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0806")  #ARP type
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x1003a    #the console port
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 2-0  L3PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=7
  tempmatchx.offset=184
  tempmatchx.length=8
  tempmatchx.set_value("11")
  tempmatchx.set_mask("ff")
  msg.matchx.append(tempmatchx)
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=12
  tempmatchx.offset= 288
  tempmatchx.length=16
  tempmatchx.set_value("12b5")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 20
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 20-0  VxLanDecap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 4
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 128
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 16
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
   
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 0
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_1])
  msg.instruction.append(tempins)
  event.connection.send(msg)

def cooper_loop_nc(event):    
  ofmatch20_1 =of.ofp_match20()
  ofmatch20_1.fieldId=0
  ofmatch20_1.offset=0
  ofmatch20_1.length=48
  
  ofmatch20_2 =of.ofp_match20()
  ofmatch20_2.fieldId=-1
  ofmatch20_2.offset=272
  ofmatch20_2.length=32
  
  ofmatch20_3 =of.ofp_match20()
  ofmatch20_3.fieldId= -1
  ofmatch20_3.offset= 336
  ofmatch20_3.length= 16
  
  ofmatch20_4 =of.ofp_match20()
  ofmatch20_4.fieldId= -1
  ofmatch20_4.offset= 160
  ofmatch20_4.length= 16
  
  ofmatch20_5 =of.ofp_match20()
  ofmatch20_5.fieldId= 2
  ofmatch20_5.offset= 96
  ofmatch20_5.length=16
  
  ofmatch20_6 =of.ofp_match20()
  ofmatch20_6.fieldId=7
  ofmatch20_6.offset=184
  ofmatch20_6.length=8
  
  ofmatch20_7 =of.ofp_match20()
  ofmatch20_7.fieldId= 12
  ofmatch20_7.offset= 288
  ofmatch20_7.length=16
  
  ##############################################################################
  #table_mod 0   MM
  ###############################################################################
  
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_1)
  #msg.flowTable.matchFieldList.append(ofmatch20_3)
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType=0  #OF_MM_TABLE
  msg.flowTable.matchFieldNum = 1
  msg.flowTable.tableSize=128
  msg.flowTable.tableId=0
  msg.flowTable.tableName="FirstEntryTable"
  msg.flowTable.keyLength=48
  event.connection.send(msg)

  ##############################################################################
  #table_mod 16  MacMap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="MacMap"
  event.connection.send(msg)
  
  
  ##############################################################################
  #table_mod 17  VNI
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VNI"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 18  VxLanEncap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanEncap"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 8  FIB
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_2)
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 1
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 32
  msg.flowTable.tableName="FIB"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 21  FIB_DT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=5
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="FIB_DT"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 19  EPAT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=3
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="EPAT"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 1 L2PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_5)
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 16
  msg.flowTable.tableName="L2PA"
  event.connection.send(msg)
  
  
   ##############################################################################
  #table_mod 2  L3PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_6)
  msg.flowTable.matchFieldList.append(ofmatch20_7)
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 24
  msg.flowTable.tableName="L3PA"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 20 VxLanDecap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=4
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanDecap"
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-0  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 0
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("6cf0498cd47b")  #IOA PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1      
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-1  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 1
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("bc305ba4e124")  #USTC PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-2  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 2
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("000000000002")  #MacMap
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 16
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
    ##############################################################################
  #flow_mod 0-3  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 3
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("90e2ba2a22ca")  #NC PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-4  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 4
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("643e8c369927")  #NC Switch MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-5  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 5
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("ffffffffffff")  #for ARP request
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 16-0  MacMap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_setfield()
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= 1
  tempmatchx.offset= 0
  tempmatchx.length= 48
  tempmatchx.set_value("90e2ba2a22ca")    #NC PC MAC
  action.fieldSetting = tempmatchx
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-0  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('9FE23D4B')    #Network Center Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('D24BE144')  #IOA Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-1  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('9FE23D4B')    #Network Center Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('72d6a6c1')  #USTC Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-0  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=128
  tempins.set_value('0800') #EthType
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=144
  tempins.set_value('4500')  #V_IHL_TOS
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=208
  tempins.set_value('4011')  #TTL  & Protocol
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=320
  tempins.set_value('12b5')  #UDP Dport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-1  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 4
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=368
  tempins.set_value('80')  #VxLan Flag
  tempins.writeLength = 8
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket()  #Total length to UDP_length
  tempins.metadataOffset= 336
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket() #Total length to  Total length 
  tempins.metadataOffset= 160
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 2
  msg.instruction.append(tempins)
  event.connection.send(msg)

  ##############################################################################
  #flow_mod 18-2  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 5
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 2
  
  tempins=of.ofp_instruction_calculatefiled()  #UDP_length + 30
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_3
  tempins.src_value = 30
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_calculatefiled()#Total_length + 50
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_4
  tempins.src_value = 50
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 3
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-3  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 3
  
  
  tempins=of.ofp_instruction_writemetadata() 
  tempins.metaDataOffset=304
  tempins.set_value('04d2') #UDP Sport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 4
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-4  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 7
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 4
  
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_calculatechecksum()
  action.checksumPosType = 1
  action.calcPosType = 1
  action.checksumPosition = 224
  action.checksumLength = 16
  action.calcStarPosition = 144
  action.calcLength = 160
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 8
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_2])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 8-0 FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("D24BE144") #IOA switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 8-1  FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("72d6a6c1") #USTC switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 21-0  FIB_DT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 9
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 5
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=32
  tempins.set_value('90e2ba2a22cb')   #NC GateWay MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-0  EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=80
  tempins.set_value('643e8c369927')   #NC switch MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x20000
  action.metadataOffset=32
  action.metadataLength=400
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-1   EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x20002
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-0   L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0800")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 2
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_6,ofmatch20_7])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-1 L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0806")  #ARP type
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x1003a    #the console port
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 2-0  L3PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=7
  tempmatchx.offset=184
  tempmatchx.length=8
  tempmatchx.set_value("11")
  tempmatchx.set_mask("ff")
  msg.matchx.append(tempmatchx)
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=12
  tempmatchx.offset= 288
  tempmatchx.length=16
  tempmatchx.set_value("12b5")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 20
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 20-0  VxLanDecap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 4
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 128
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 16
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
   
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 0
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_1])
  msg.instruction.append(tempins)
  event.connection.send(msg)

def cooper_loop_ioa(event):    
  ofmatch20_1 =of.ofp_match20()
  ofmatch20_1.fieldId=0
  ofmatch20_1.offset=0
  ofmatch20_1.length=48
  
  ofmatch20_2 =of.ofp_match20()
  ofmatch20_2.fieldId=-1
  ofmatch20_2.offset=272
  ofmatch20_2.length=32
  
  ofmatch20_3 =of.ofp_match20()
  ofmatch20_3.fieldId= -1
  ofmatch20_3.offset= 336
  ofmatch20_3.length= 16
  
  ofmatch20_4 =of.ofp_match20()
  ofmatch20_4.fieldId= -1
  ofmatch20_4.offset= 160
  ofmatch20_4.length= 16
  
  ofmatch20_5 =of.ofp_match20()
  ofmatch20_5.fieldId= 2
  ofmatch20_5.offset= 96
  ofmatch20_5.length=16
  
  ofmatch20_6 =of.ofp_match20()
  ofmatch20_6.fieldId=7
  ofmatch20_6.offset=184
  ofmatch20_6.length=8
  
  ofmatch20_7 =of.ofp_match20()
  ofmatch20_7.fieldId= 12
  ofmatch20_7.offset= 288
  ofmatch20_7.length=16
  
  ##############################################################################
  #table_mod 0   MM
  ###############################################################################
  
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_1)
  #msg.flowTable.matchFieldList.append(ofmatch20_3)
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType=0  #OF_MM_TABLE
  msg.flowTable.matchFieldNum = 1
  msg.flowTable.tableSize=128
  msg.flowTable.tableId=0
  msg.flowTable.tableName="FirstEntryTable"
  msg.flowTable.keyLength=48
  event.connection.send(msg)

  ##############################################################################
  #table_mod 16  MacMap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="MacMap"
  event.connection.send(msg)
  
  
  ##############################################################################
  #table_mod 17  VNI
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VNI"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 18  VxLanEncap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 128
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanEncap"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 8  FIB
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_2)
  msg.flowTable.tableId=0
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 1
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 32
  msg.flowTable.tableName="FIB"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 21  FIB_DT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=5
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="FIB_DT"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 19  EPAT
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=3
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="EPAT"
  event.connection.send(msg)
  
  ##############################################################################
  #table_mod 1 L2PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_5)
  msg.flowTable.tableId=1
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 16
  msg.flowTable.tableName="L2PA"
  event.connection.send(msg)
  
  
   ##############################################################################
  #table_mod 2  L3PA
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.matchFieldList.append(ofmatch20_6)
  msg.flowTable.matchFieldList.append(ofmatch20_7)
  msg.flowTable.tableId=2
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 0
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 24
  msg.flowTable.tableName="L3PA"
  event.connection.send(msg)
  
   ##############################################################################
  #table_mod 20 VxLanDecap
  ###############################################################################
  msg =of.ofp_table_mod()
  msg.flowTable.tableId=4
  msg.flowTable.command=0 #OFPTC_ADD
  msg.flowTable.tableType = 3
  msg.flowTable.tableSize = 100
  msg.flowTable.keyLength= 0
  msg.flowTable.tableName="VxLanDecap"
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-0  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 0
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("90e2ba2a22ca")  #NC PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0      
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-1  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 0
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 1
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("bc305ba4e124")  #USTC PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0    #because the nc node is down, when nc node up is 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-2  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 2
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("000000000001")  #MacMap
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 16
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
    ##############################################################################
  #flow_mod 0-3  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 3
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("6cf0498cd47b")  #IOA PC MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-4  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 4
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("643e8c3dc61f")  #IOA Switch MAC
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 0-5  MM
  ###############################################################################
 
  msg=of.ofp_flow_mod()
  msg.counterId = 1
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0  
  msg.tableType = 0 #OF_MM_TABLE
  msg.priority = 0
  msg.index = 5
  
  #matchx 1
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=0
  tempmatchx.offset=0
  tempmatchx.length=48
  tempmatchx.set_value("ffffffffffff")  #for ARP request
  tempmatchx.set_mask("ffffffffffff")
  msg.matchx.append(tempmatchx)

  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 1
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_5])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 16-0  MacMap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_setfield()
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= 1
  tempmatchx.offset= 0
  tempmatchx.length= 48
  tempmatchx.set_value("6cf0498cd47b")    #IOA PC MAC
  action.fieldSetting = tempmatchx
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 17
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0  #because
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-0  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('c0a82f49')    #IOA Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('9FE23D4B')  #NC Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 17-1  VNI
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 2
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=240
  tempins.set_value('c0a82f49')    #IOA Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)    
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=272
  tempins.set_value('72d6a6c1')  #USTC Switch IP
  tempins.writeLength = 32
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset= 400
  tempins.set_value('000001')     #VNI
  tempins.writeLength = 24
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-0  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 3
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=128
  tempins.set_value('0800') #EthType
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=144
  tempins.set_value('4500')  #V_IHL_TOS
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=208
  tempins.set_value('4011')  #TTL  & Protocol
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=320
  tempins.set_value('12b5')  #UDP Dport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 1
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-1  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 4
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=368
  tempins.set_value('80')  #VxLan Flag
  tempins.writeLength = 8
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket()  #Total length to UDP_length
  tempins.metadataOffset= 336
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_writemetadatafrompacket() #Total length to  Total length 
  tempins.metadataOffset= 160
  tempins.packetOffset = 128
  tempins.writeLength = 16
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 2
  msg.instruction.append(tempins)
  event.connection.send(msg)

  ##############################################################################
  #flow_mod 18-2  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 5
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 2
  
  tempins=of.ofp_instruction_calculatefiled()  #UDP_length + 30
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_3
  tempins.src_value = 30
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_calculatefiled()#Total_length + 50
  tempins.calcType = 0
  tempins.src_valueType = 0    #0: use srcField_Value; 1: use srcField;
  tempins.des_field = ofmatch20_4
  tempins.src_value = 50
  #tempins.src_field = ofp_match20()
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 3
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-3  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 3
  
  
  tempins=of.ofp_instruction_writemetadata() 
  tempins.metaDataOffset=304
  tempins.set_value('04d2') #UDP Sport
  tempins.writeLength = 16
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 18
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 4
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 18-4  VxLanEncap
  ###############################################################################
  
  msg=of.ofp_flow_mod()
  msg.counterId = 7
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 3
  msg.priority = 0
  msg.index = 4
  
  tempins=of.ofp_instruction_applyaction()
  action = of.ofp_action_calculatechecksum()
  action.checksumPosType = 1
  action.calcPosType = 1
  action.checksumPosition = 224
  action.checksumLength = 16
  action.calcStarPosition = 144
  action.calcLength = 160
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
    
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 8
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_2])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 8-0 FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("9FE23D4B") #NC switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 8-1  FIB
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 8
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 0
  msg.tableType = 1
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId= -1
  tempmatchx.offset= 272
  tempmatchx.length= 32
  tempmatchx.set_value("72d6a6c1") #USTC switch IP
  tempmatchx.set_mask("ffffffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 21
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 21-0  FIB_DT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 9
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 5
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=32
  tempins.set_value('70f96d594742')   #IOA GateWay MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 19
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)

  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-0  EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_writemetadata()
  tempins.metaDataOffset=80
  tempins.set_value('643e8c3dc61f')   #IOA switch MAC
  tempins.writeLength = 48
  msg.instruction.append(tempins)
  
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x10043
  action.metadataOffset=32
  action.metadataLength=400
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 19-1   EPAT
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 10
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 3
  msg.tableType = 3
  msg.priority = 0
  msg.index = 1
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x10041
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-0   L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0800")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 2
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_6,ofmatch20_7])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 1-1 L2PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 1
  msg.tableType = 0
  msg.priority = 0
  msg.index = 1
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=2
  tempmatchx.offset=96
  tempmatchx.length=16
  tempmatchx.set_value("0806")  #ARP type
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_output()
  action.portId=0x1003a    #the console port
  action.metadataOffset=0
  action.metadataLength=0
  action.packetOffset=0
  tempins.actionList.append(action) 
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  
  ##############################################################################
  #flow_mod 2-0  L3PA
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 2
  msg.tableType = 0
  msg.priority = 0
  msg.index = 0
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=7
  tempmatchx.offset=184
  tempmatchx.length=8
  tempmatchx.set_value("11")
  tempmatchx.set_mask("ff")
  msg.matchx.append(tempmatchx)
  
  tempmatchx=of.ofp_matchx()
  tempmatchx.fieldId=12
  tempmatchx.offset= 288
  tempmatchx.length=16
  tempmatchx.set_value("12b5")
  tempmatchx.set_mask("ffff")
  msg.matchx.append(tempmatchx)
  
  tempins=of.ofp_instruction_gotodirecttable()
  tempins.nextTableId = 20
  tempins.indexType = 0
  tempins.packetOffset= 0
  tempins.indexValue = 0
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
  ##############################################################################
  #flow_mod 20-0  VxLanDecap
  ###############################################################################
  msg=of.ofp_flow_mod()
  msg.counterId = 6
  msg.cookie = 0
  msg.cookieMask = 0
  msg.tableId = 4
  msg.tableType = 3
  msg.priority = 0
  msg.index = 0
  
  tempins=of.ofp_instruction_applyaction()
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 128
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  tempins.actionList.append(action)
  
  action=of.ofp_action_deletefield()
  action.tagPosition = 0
  action.tagLengthValueType = 0
  action.tagLengthValue = 16
  tempins.actionList.append(action)
  msg.instruction.append(tempins)
   
  tempins=of.ofp_instruction_gototable()
  tempins.nextTableId= 0
  tempins.packetOffset=0
  tempins.matchList.extend([ofmatch20_1])
  msg.instruction.append(tempins)
  event.connection.send(msg)
  
    
def _handle_ConnectionUp (event):
    if event.connection.dpid == 2352562177:   #USTC  8c394001
        print '----USTC-----'
        core.PofManager.set_port_pof_enable(event.dpid, 0x10041) 
        core.PofManager.set_port_pof_enable(event.dpid, 0x10043) 
        cooper_loop_ustc(event)
        
    elif event.connection.dpid == 2352388391:   #NC  8c369927
        print '-----NC-------'
        core.PofManager.set_port_pof_enable(event.dpid, 0x20000) 
        core.PofManager.set_port_pof_enable(event.dpid, 0x20002) 
        cooper_loop_nc(event)
        
    elif event.connection.dpid == 2352858652:  #IOA  8c3dc61c
        print '----IOA-------'
        core.PofManager.set_port_pof_enable(event.dpid, 0x10041) 
        core.PofManager.set_port_pof_enable(event.dpid, 0x10043) 
        cooper_loop_ioa(event)
    
def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  log.info("Hub running2.")
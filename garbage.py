import subprocess
import jarray
import inspect
import os
from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

import csv


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class EvtxIOCAnalysisIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "EVTX IOC Hunter22"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Detection of IOCs in EVTX Logs"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isDataSourceIngestModuleFactory(self):
        return True
    
##    def getDefaultIngestJobSettings(self):
##        return GenericIngestModuleJobSettings()
##    
##    def getIngestJobSettingsPanel(self, settings):
##        if not isinstance(settings, GenericIngestModuleJobSettings):
##            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
##        self.settings = settings
##        return Process_EVTX1WithUISettingsPanel(self.settings)
    
    # can return null if isFileIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return EvtxIOCAnalysisIngestModule(self.settings)


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class EvtxIOCAnalysisIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(EvtxIOCAnalysisIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    
    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Events = []
        
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context

        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.csv")
        #      self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evtxIOC_prototypev5_sigma.exe")
        #      if not os.path.exists(self.path_to_exe): raise IngestModuleException("Windows EXE File does not exists")
        # else:
        #     self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evtxIOC_prototypev5_sigma")
        #     if not os.path.exists(self.path_to_exe): raise IngestModuleException(" Linux EXE File does not exists")

        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):
        #skCase = Case.getCurrentCase().getSleuthkitCase();
        skCase = Case.getCurrentCase().getServices().getBlackboard()
        #skCase_Tran = skCase.beginTransaction()
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sum_ioc_evtx = skCase.getOrAddArtifactType( "SUM_IOC_EVTX_LOGS", "Windows Event Logs")     
        except:		
            self.log(Level.INFO, "Error in Artifacts Creation, some artifacts may be missing.")
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_ioc_evtx = skCase.getOrAddArtifactType( "IOC_EVTX_LOGS", "Detailed Windows Event Logs")
        except:		
            self.log(Level.INFO, "Error in Artifacts Creation, some artifacts may be missing.")            

        try:
            attID_ev_fn = skCase.getOrAddAttributeType("EVTX_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Log File Name")
            self.log(Level.INFO, str(attID_ev_fn))   
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Log File Name. == ")
        try:
            attID_ev_rc = skCase.getOrAddAttributeType("TSK_EVTX_RECOVERED_RECORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recovered Record")
            self.log(Level.INFO, str(attID_ev_rc))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Recovered Record. == ")
        try:
            attID_ev_cn = skCase.getOrAddAttributeType("TSK_EVTX_COMPUTER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
            self.log(Level.INFO, str(attID_ev_cn))  

        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Computer Name. == ")
        try:
            attID_ev_ei = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Identifier")
            self.log(Level.INFO, str(attID_ev_ei))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Log File Name. == ")
        try:
            attID_ev_eiq = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_IDENTIFIER_QUALIFERS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Identifier Qualifiers")
            self.log(Level.INFO, str(attID_ev_eiq))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Identifier Qualifiers. == ")
        try:
            attID_ev_el = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Level")
            self.log(Level.INFO, str(attID_ev_el))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Level. == ")
        try:
            attID_ev_oif = skCase.getOrAddAttributeType("TSK_EVTX_OFFSET_IN_FILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Offset In File")
            self.log(Level.INFO, str(attID_ev_oif))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Offset In File. == ")
        try:
            attID_ev_id = skCase.getOrAddAttributeType("TSK_EVTX_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Identifier")
            self.log(Level.INFO, str(attID_ev_id))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Identifier. == ")
        try:
            attID_ev_sn = skCase.getOrAddAttributeType("TSK_EVTX_SOURCE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Source Name")
            self.log(Level.INFO, str(attID_ev_sn))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Source Name. == ")
        try:
            attID_ev_usi = skCase.getOrAddAttributeType("TSK_EVTX_USER_SECURITY_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Security ID")
            self.log(Level.INFO, str(attID_ev_usi))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - User Security ID. == ")
        try:
            attID_ev_et = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time")
            self.log(Level.INFO, str(attID_ev_et))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Time. == ")
        try:
            attID_ev_ete = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_TIME_EPOCH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time Epoch")
            self.log(Level.INFO, str(attID_ev_ete))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Identifier. == ")
        try:
            attID_ev_dt = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_DETAIL_TEXT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Detail")
            self.log(Level.INFO, str(attID_ev_dt))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Detail. == ")
        try:
            attID_ev_cnt = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_ID_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Id Count")
            self.log(Level.INFO, str(attID_ev_cnt))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event ID Count. == ")
        try:
            attID_ioc_rule_name = skCase.getOrAddAttributeType("TSK_EVTX_IOC_RULE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IOC Rule Name")
            self.log(Level.INFO, str(attID_ioc_rule_name))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - IOC Rule Name. == ")
        try:
            attID_no_of_evt = skCase.getOrAddAttributeType("TSK_EVTX_NO_OF_EVT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Number of Event")
            self.log(Level.INFO, str(attID_no_of_evt))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Number of Event. == ")        
        
        self.log(Level.INFO, "Get Artifacts after they were created.")
        #Get the new artifacts and attributes that were just created
        # artID_sum_ioc_evtx = skCase.getArtifactTypeID("SUM_IOC_EVTX_LOGS")
        # artID_sum_ioc_evtx_evt = skCase.getArtifactType("SUM_IOC_EVTX_LOGS")
        # artID_ioc_evtx = skCase.getArtifactTypeID("IOC_EVTX_LOGS")
        # artID__ioc_evtx_evt = skCase.getArtifactType("IOC_EVTX_LOGS")
        #attID_ev_fn = skCase.getAttributeType("TSK_EVTX_FILE_NAME")
        # attID_ev_rc = skCase.getAttributeType("TSK_EVTX_RECOVERED_RECORD")			 
        # attID_ev_cn = skCase.getAttributeType("TSK_EVTX_COMPUTER_NAME")			 
        # attID_ev_ei = skCase.getAttributeType("TSK_EVTX_EVENT_IDENTIFIER")
        # attID_ev_eiq = skCase.getAttributeType("TSK_EVTX_EVENT_IDENTIFIER_QUALIFERS")
        # attID_ev_el = skCase.getAttributeType("TSK_EVTX_EVENT_LEVEL")
        # attID_ev_oif = skCase.getAttributeType("TSK_EVTX_OFFSET_IN_FILE")
        # attID_ev_id = skCase.getAttributeType("TSK_EVTX_IDENTIFIER")
        # attID_ev_sn = skCase.getAttributeType("TSK_EVTX_SOURCE_NAME")
        # attID_ev_usi = skCase.getAttributeType("TSK_EVTX_USER_SECURITY_ID")
        # attID_ev_et = skCase.getAttributeType("TSK_EVTX_EVENT_TIME")
        # attID_ev_ete = skCase.getAttributeType("TSK_EVTX_EVENT_TIME_EPOCH")
        # attID_ev_dt = skCase.getAttributeType("TSK_EVTX_EVENT_DETAIL_TEXT")
        # attID_ev_cnt = skCase.getAttributeType("TSK_EVTX_EVENT_ID_COUNT")
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        #Find the Windows Event Log Files
        files = []		
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        # if self.List_Of_Events[0] == 'ALL':
        files = fileManager.findFiles(dataSource, "ECSSv9 Module 01 Information Security Fundamentals.pdc")
        # else:
        #     for eventlog in self.List_Of_Events:
        #         file_name = fileManager.findFiles(dataSource, eventlog)
        #         files.extend(file_name)
 
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        #progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        
        # Create Event Log directory in temp directory, if it exists then continue on processing		
        # Temp_Dir = Case.getCurrentCase().getTempDirectory()
        # self.log(Level.INFO, "create Directory " + Temp_Dir)
        # temp_dir = os.path.join(Temp_Dir, "EvtxLogs")
        # try:
        #     os.mkdir(temp_dir)
        # except:
        #     self.log(Level.INFO, "Event Log Directory already exists " + temp_dir)
            
        # Write out each Event Log file to the temp directory
            
            # Check if the user pressed cancel while we were busy
            # if self.context.isJobCancelled():
            #     return IngestModule.ProcessResult.OK

            # #self.log(Level.INFO, "Processing file: " + file.getName())
            # fileCount += 1

            # # Save the DB locally in the temp folder. use file id as name to reduce collisions
            # Result_Path = os.path.join(temp_dir, file.getName())
            # ContentUtils.writeToFile(file, File(Result_Path))
                        
        # Run the EXE, saving output to a sqlite database
        # self.log(Level.INFO, "Running program on data source " + self.path_to_exe + " parm 1 == " + temp_dir + "  Parm 2 == " + os.path.join(temp_dir, "EventLogs.db3"))
        # subprocess.Popen([self.path_to_exe, temp_dir, os.path.join(Temp_Dir, "Analysis_Results.csv")]).communicate()[0]   
            
        # # Set the database to be read to the one created by our program
        # Result_Path = os.path.join(Case.getCurrentCase().getTempDirectory(), "Analysis_Results.csv")
        # self.log(Level.INFO, "Path to the Eventlogs database file created == " + Result_Path)
        
                        
        # Read the Output file from EXE
        # Cycle through each row and create artifacts
        #self.log(Level.INFO, self.path_to_exe)
        reader = csv.DictReader(open(self.path_to_exe))
        for row in reader:
            Computer_Name = str(row["Computer_Name"])
            Event_Identifier = str(row["Event_Identifier"])
            Event_Level = str(row["Event_Level"])
            Event_Source_Name = str(row["Event_Source_Name"])
            Event_User_Security_Identifier = str(row["Event_User_Security_Identifier"])             
            Event_Time = str(row["Event_Time"])
            Event_Detail_Text = str(row["Event_Detail_Text"])

        #Computer_Name = "Computer_Name"

        # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
        # Make artifact for IOC_EVTX_LOGS
            try:
                art = files[0].newArtifact(artID_ioc_evtx.getTypeID())
            except: 
                self.log(Level.INFO, "Error")
            # try:
            art.addAttributes(((BlackboardAttribute(attID_ev_cn, EvtxIOCAnalysisIngestModuleFactory.moduleName, Computer_Name)), \
                                    (BlackboardAttribute(attID_ev_ei, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_Identifier)), \
                                    (BlackboardAttribute(attID_ev_el, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_Level)), \
                                    (BlackboardAttribute(attID_ev_sn, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_Source_Name)), \
                                    (BlackboardAttribute(attID_ev_usi, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_User_Security_Identifier)), \
                                    (BlackboardAttribute(attID_ev_et, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_Time)), \
                                    (BlackboardAttribute(attID_ev_dt, EvtxIOCAnalysisIngestModuleFactory.moduleName, Event_Detail_Text)))) 
        
            # except Exception as e:
            #      #self.log(Level.INFO, "Error in adding")
            #     self.log(Level.INFO, e)
            # try:
            skCase.postArtifact(art, EvtxIOCAnalysisIngestModuleFactory.moduleName)
            # except:
            #     self.log(Level.INFO, "Error posting artifact")

        
    
        reader2 = csv.DictReader(open(self.path_to_exe))
        for row in reader2:
            IOC_Rule_Name = str(row["EVTX_Name"])
            No_of_Event = str(row["No_of_Evt"])
        
           
        # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
        # Make artifact for SUM_IOC_EVTX_LOGS
            art2 = files[0].newArtifact(artID_sum_ioc_evtx.getTypeID())

            art2.addAttributes(((BlackboardAttribute(attID_ioc_rule_name, EvtxIOCAnalysisIngestModuleFactory.moduleName, IOC_Rule_Name)), \
                                (BlackboardAttribute(attID_no_of_evt, EvtxIOCAnalysisIngestModuleFactory.moduleName, No_of_Event))))
           
            try:
                skCase.postArtifact(art2, EvtxIOCAnalysisIngestModuleFactory.moduleName)
            except:
                self.log(Level.INFO, "Error posting artifact2")

            # Fire an event to notify the UI and others that there are new artifacts  

        # IngestServices.getInstance().fireModuleDataEvent(
        #     ModuleDataEvent(EvtxIOCAnalysisIngestModuleFactory.moduleName, artID_sum_ioc_evtx_evt, None))
        # IngestServices.getInstance().fireModuleDataEvent(
        #     ModuleDataEvent(EvtxIOCAnalysisIngestModuleFactory.moduleName, artID_ioc_evtx_evt, None))

        return IngestModule.ProcessResult.OK
        



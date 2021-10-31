import subprocess
import jarray
import inspect
import os
import csv

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.io import File
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.casemodule.services import Blackboard
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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class EvtxIOCAnalysisIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "EVTX IOC Hunter"

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
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evtxIOC_prototypev6_sigma.exe")
            if not os.path.exists(self.path_to_exe): raise IngestModuleException("Windows EXE File does not exists")
            self.path_to_rulefile = os.path.join(os.path.dirname(os.path.abspath(__file__)), r'rules\\rules_windows_generic.json')
        else:
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evtxIOC_prototypev6_sigma")
            if not os.path.exists(self.path_to_exe): raise IngestModuleException(" Linux EXE File does not exists")

        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):
        #retrieve blackboard
        skCase = Case.getCurrentCase().getServices().getBlackboard()   

        #Create all of the necessary artifacts
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sum_ioc_evtx = skCase.getOrAddArtifactType( "SUM_IOC_EVTX_LOGS", "Summary of IOCs in Windows Event Logs")     
        except:		
            self.log(Level.INFO, "Error in Artifacts Creation, some artifacts may be missing.")
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_ioc_evtx = skCase.getOrAddArtifactType( "IOC_EVTX_LOGS", "Detailed Windows Event Logs")
        except:		
            self.log(Level.INFO, "Error in Artifacts Creation, some artifacts may be missing.")  
        try:
            attID_evt_ch = skCase.getOrAddAttributeType("TSK_EVTX_CHANNEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Channel")
            self.log(Level.INFO, str(attID_evt_ch))   
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Channel. == ")
        try:
            attID_evt_cn = skCase.getOrAddAttributeType("TSK_EVTX_COMPUTER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
            self.log(Level.INFO, str(attID_evt_cn))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Computer Name. == ")
        try:
            attID_evt_ei = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event ID")
            self.log(Level.INFO, str(attID_evt_ei))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Log File Name. == ")
        try:
            attID_evt_epid = skCase.getOrAddAttributeType("TSK_EVTX_EXEC_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Execution Process ID")
            self.log(Level.INFO, str(attID_evt_epid))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Log File Name. == ")
        try:
            attID_evt_pgid = skCase.getOrAddAttributeType("TSK_EVTX_PROVIDER_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider GUID")
            self.log(Level.INFO, str(attID_evt_pgid))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Provider GUID. == ")
        try:
            attID_evt_el = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Level")
            self.log(Level.INFO, str(attID_evt_el))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Level. == ")
        try:
            attID_evt_pn = skCase.getOrAddAttributeType("TSK_EVTX_PROVIDER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider Name")
            self.log(Level.INFO, str(attID_evt_pn))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Offset In File. == ")
        try:
            attID_evt_su = skCase.getOrAddAttributeType("TSK_SUBJECT_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Username")
            self.log(Level.INFO, str(attID_evt_su))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Subject Username. == ")
        try:
            attID_evt_sdn = skCase.getOrAddAttributeType("TSK_EVTX_SUBJECT_DOMAIN_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Domain Name")
            self.log(Level.INFO, str(attID_evt_sdn))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Subject Domain Name. == ")
        try:
            attID_evt_et = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time")
            self.log(Level.INFO, str(attID_evt_et))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Time. == ")
        try:
            attID_evt_rn = skCase.getOrAddAttributeType("TSK_EVTX_RULE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IOC Rule Name")
            self.log(Level.INFO, str(attID_evt_rn))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - IOC Rule Name. == ")
        try:
            attID_evt_rd = skCase.getOrAddAttributeType("TSK_EVTX_RULE_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IOC Rule Description")
            self.log(Level.INFO, str(attID_evt_rd))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - IOC Rule Description. == ")
        try:
            attID_evt_ec = skCase.getOrAddAttributeType("TSK_EVTX_EVENT_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Count")
            self.log(Level.INFO, str(attID_evt_ec))  
        except:		
                self.log(Level.INFO, "== Error in Attributes Creation - Event Count. == ")
        
        progressBar.switchToIndeterminate()

        #Find the Windows Event Log Files
        files = []
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.evtx")
        # files = []		
        # fileManager = Case.getCurrentCase().getServices().getFileManager()
        # # if self.List_Of_Events[0] == 'ALL':
        # files = fileManager.findFiles(dataSource, "ECSSv9 Module 01 Information Security Fundamentals.pdc")
        # self.log(Level.INFO, str(files[0].getName()))
        # numFiles = len(files)
        # self.log(Level.INFO, "found " + str(numFiles) + " files")
        # #progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        
        #Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        temp_dir = os.path.join(Temp_Dir, "analysisCSV")
        try:
            os.mkdir(temp_dir)
        except:
            self.log(Level.INFO, "Event Log Directory already exists " + temp_dir)
            
        # Write out each Event Log file to the temp directory
        for file in files:
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # # Save the DB locally in the temp folder. use file id as name to reduce collisions
            Evtx_Path = os.path.join(temp_dir, file.getName())
            ContentUtils.writeToFile(file, File(Evtx_Path))
            self.log(Level.INFO, Evtx_Path)

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source " + self.path_to_exe + " parm 1 == " + "  Parm 2 == " + temp_dir)
        subprocess.Popen([self.path_to_exe, "-f", str(temp_dir), "-r", self.path_to_rulefile, "-o", str(temp_dir)]).wait()
        # # Set the database to be read to the one created by our program

        filelist = []
        for f in os.listdir(temp_dir):
            if f.endswith(".csv") and f != "logs.csv":
                if f == "Summary.csv":
                    summary_file_path = os.path.join(temp_dir, "Summary.csv")
                else:
                    filelist.append(f)

        # reader = csv.DictReader(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs.csv")))
        # art2 = []
        # for row in reader:
        #     art = files[0].newArtifact(artID_ioc_evtx.getTypeID())
        #     for i in range(len(col_name)):
        #         var = str(row[col_name[i]]) 
        #         # if (row[col_name[i]] == None):
        #         #     var = ""
        #         art2.append(BlackboardAttribute(att_list[i], EvtxIOCAnalysisIngestModuleFactory.moduleName, var))
        #         # art.addAttribute(BlackboardAttribute(att_list[i], EvtxIOCAnalysisIngestModuleFactory.moduleName, var))
            

        # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
        # Make artifact for IOC_EVTX_LOGS
        # reader = csv.DictReader(open(self.path_to_exe))
        for path in filelist:
            Result_Path = os.path.join(temp_dir, path)
            self.log(Level.INFO, "Path to the IOC Result file created == " + Result_Path)
            reader = csv.DictReader(open(str(Result_Path)))
            for row in reader:             
                try:
                    for file in files:
                        if (file.getName() == str(row["FileName"])):           
                            art = file.newArtifact(artID_ioc_evtx.getTypeID())
                            break
                except: self.log(Level.SEVERE, "Error in adding new Artifact")

                art.addAttributes(((BlackboardAttribute(attID_evt_cn, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                        (BlackboardAttribute(attID_evt_ch, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                        (BlackboardAttribute(attID_evt_pn, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                        (BlackboardAttribute(attID_evt_ei, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                        (BlackboardAttribute(attID_evt_el, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                        (BlackboardAttribute(attID_evt_su, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Subjectusername"]))), \
                                        (BlackboardAttribute(attID_evt_sdn, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Subjectdomainname"]))), \
                                        (BlackboardAttribute(attID_evt_et, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["TimeCreated_SystemTime"]))), \
                                        (BlackboardAttribute(attID_evt_epid, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Execution_ProcessID"]))), \
                                        (BlackboardAttribute(attID_evt_pgid, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Provider_Guid"])))))
                                        # (BlackboardAttribute(attID_evt_dt, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Details"]))))) 
    
                try: skCase.postArtifact(art, EvtxIOCAnalysisIngestModuleFactory.moduleName)
                except: self.log(Level.INFO, "Error in posting artifact ")   
             
        reader2 = csv.DictReader(open(str(summary_file_path)))
        for row in reader2:
        # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
        # Make artifact for SUM_IOC_EVTX_LOGS
            art2 = files[0].newArtifact(artID_sum_ioc_evtx.getTypeID())

            art2.addAttributes(((BlackboardAttribute(attID_evt_rn, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Title"]))), \
                                (BlackboardAttribute(attID_evt_rd, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                (BlackboardAttribute(attID_evt_ec, EvtxIOCAnalysisIngestModuleFactory.moduleName, str(row["Count"])))))
           
            try:
                skCase.postArtifact(art2, EvtxIOCAnalysisIngestModuleFactory.moduleName)
            except:
                self.log(Level.INFO, "Error in posting artifact ")

        return IngestModule.ProcessResult.OK
        



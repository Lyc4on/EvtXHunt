import subprocess
import inspect
import os
import csv

from java.io import File
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Blackboard

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class EvtXHuntAnalysisIngestModuleFactory(IngestModuleFactoryAdapter):
    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "EvtXHunt"

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
        return EvtXHuntAnalysisIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class EvtXHuntAnalysisIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(EvtXHuntAnalysisIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    
    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        #check if platform is windows and set the exe path and rule path
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "EvtXHunt.exe")
            if not os.path.exists(self.path_to_exe): raise IngestModuleException("Windows EXE File does not exists")
            self.path_to_rulefile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):
        #retrieve blackboard
        bboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        #Create all of the necessary artifacts with the relevant strings and its value type
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sum_ioc_evtx = bboard.getOrAddArtifactType( "SUM_IOC_EVTX_LOGS", "Summary of IOCs in Windows Event Logs")     
        except: self.log(Level.INFO, "Error in Artifacts Creation, some artifacts may be missing.")
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_ioc_evtx = bboard.getOrAddArtifactType( "IOC_EVTX_LOGS", "Detailed Windows Event Logs")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")  
        
        try: attID_evt_ch = bboard.getOrAddAttributeType("TSK_EVTX_CHANNEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Channel")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Channel. == ")
        
        try: attID_evt_cn = bboard.getOrAddAttributeType("TSK_EVTX_COMPUTER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Computer Name. == ")
        
        try: attID_evt_ei = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log File Name. == ")
        
        try: attID_evt_epid = bboard.getOrAddAttributeType("TSK_EVTX_EXEC_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Execution Process ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log File Name. == ")
        
        try: attID_evt_pgid = bboard.getOrAddAttributeType("TSK_EVTX_PROVIDER_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider GUID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Provider GUID. == ")
        
        try: attID_evt_el = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Level")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Level. == ")
        
        try: attID_evt_pn = bboard.getOrAddAttributeType("TSK_EVTX_PROVIDER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Offset In File. == ")
       
        try: attID_evt_su = bboard.getOrAddAttributeType("TSK_SUBJECT_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Username")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject Username. == ")
       
        try: attID_evt_sdn = bboard.getOrAddAttributeType("TSK_EVTX_SUBJECT_DOMAIN_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Domain Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject Domain Name. == ")
        
        try: attID_evt_et = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Time. == ")
        
        try: attID_evt_rn = bboard.getOrAddAttributeType("TSK_EVTX_RULE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IOC Rule Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - IOC Rule Name. == ")
       
        try: attID_evt_rd = bboard.getOrAddAttributeType("TSK_EVTX_RULE_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IOC Rule Description")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - IOC Rule Description. == ")
       
        try: attID_evt_ec = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Count")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Count. == ")
        
        #Find the Windows Event Log Files
        progressBar.switchToDeterminate(4)
        files = []
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.evtx")
        self.log(Level.INFO, "found " + str(len(files)) + " Evtx log files")
        fileCount = 0


        #Create analysisCSV folder in the temp directory
        progressBar.progress(1)
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        temp_dir = os.path.join(Temp_Dir, "analysisCSV")
        try: os.mkdir(temp_dir)
        except: self.log(Level.INFO, "analysisCSV Directory already exists " + temp_dir)
            
        # Write out each Evtx Log file to the temp directory
        for file in files:
            # Check if the user pressed cancel 
            if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
            fileCount += 1
            # # Save all the evtx files locally in the temp directory
            ContentUtils.writeToFile(file, File(os.path.join(temp_dir, file.getName())))

        # Run the EXE and the csv files are save to the temp directory
        progressBar.progress(2)
        self.log(Level.INFO, "Running exe file on the data source :" + self.path_to_exe + " -f" + temp_dir + " -r " + self.path_to_rulefile + " -o " +temp_dir)
        subprocess.Popen([self.path_to_exe, "-f", str(temp_dir), "-r", self.path_to_rulefile, "-o", str(temp_dir)]).wait()
        # wait for the csv files to be written
        while "eventlog.csv" not in os.listdir(temp_dir): self.log(Level.INFO, "Waiting for the csv files to be written")
        filelist = []
        #loop through the temp directory 
        for f in os.listdir(temp_dir):
            #check if csv files that is not logs.csv exists
            if f.endswith(".csv") and f != "eventlog.csv":
                #check if cfile is summary.csv and if so, store the path into summary_file_path
                if f == "Summary.csv": summary_file_path = os.path.join(temp_dir, "Summary.csv")
                # append any other csv files into filelist
                else: filelist.append(f)
        #check if there is any result of the IOC by checking the number of csv files produce by the exe
        if not filelist:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "EvtXHunt", " No IOCs are found." )
            IngestServices.getInstance().postMessage(message)
            return IngestModule.ProcessResult.OK
            
        # Create an artifact on the blackboard
        # Make artifact for IOC_EVTX_LOGS 
        progressBar.progress(3)
        #loop through filelist so as to craft the path to the csv files
        for path in filelist:
            Result_Path = os.path.join(temp_dir, path)
            #Read each line of the csv file 
            for row in csv.DictReader(open(str(Result_Path))):             
                try:
                    for file in files:
                        #check the file name and create and attach the artifact to the file 
                        if (file.getName() == str(row["FileName"])):           
                            art = file.newArtifact(artID_ioc_evtx.getTypeID())
                            break
                except: self.log(Level.SEVERE, "Error in adding new Artifact")
                #add attributes to the artifact
                self.log(Level.INFO, "Adding new Artifact")
                art.addAttributes(((BlackboardAttribute(attID_evt_rn, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["SIGMA Rule"]))), \
                                    (BlackboardAttribute(attID_evt_rd, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["SIGMA Description"]))), \
                                    (BlackboardAttribute(attID_evt_cn, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                    (BlackboardAttribute(attID_evt_ch, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                    (BlackboardAttribute(attID_evt_pn, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                    (BlackboardAttribute(attID_evt_ei, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                    (BlackboardAttribute(attID_evt_el, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                    (BlackboardAttribute(attID_evt_su, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Subjectusername"]))), \
                                    (BlackboardAttribute(attID_evt_sdn, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Subjectdomainname"]))), \
                                    (BlackboardAttribute(attID_evt_et, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["TimeCreated_SystemTime"]))), \
                                    (BlackboardAttribute(attID_evt_epid, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Execution_ProcessID"]))), \
                                    (BlackboardAttribute(attID_evt_pgid, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Provider_Guid"])))))
                #post the artifact to the blackboard to display 
                try: bboard.postArtifact(art, EvtXHuntAnalysisIngestModuleFactory.moduleName)
                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art.getDisplayName())   

        # Create an artifact on the blackboard
        # Make artifact for SUM_IOC_EVTX_LOGS
        progressBar.progress(4)
        #Read each line of the summary.csv file 
        for row in csv.DictReader(open(str(summary_file_path))):
        #create and attach the artifact to the file
            art2 = files[0].newArtifact(artID_sum_ioc_evtx.getTypeID())
            #add attributes to the artifact
            art2.addAttributes(((BlackboardAttribute(attID_evt_rn, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["SIGMA Rule Name"]))), \
                                (BlackboardAttribute(attID_evt_rd, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["SIGMA Rule Description"]))), \
                                (BlackboardAttribute(attID_evt_ec, EvtXHuntAnalysisIngestModuleFactory.moduleName, str(row["Count"])))))
            #post the artifact to the blackboard to display 
            try: bboard.postArtifact(art2, EvtXHuntAnalysisIngestModuleFactory.moduleName)
            except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art2.getDisplayName())  
       
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, "EvtXHunt", " EvtXHunt execution completed successfully." ))

        return IngestModule.ProcessResult.OK
        



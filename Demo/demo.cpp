#include <LogIt.h>
#include <SnmpBackend.h>
#include <SnmpDefinitions.h>
#include <MuleLogComponents.h>

int main()
{
    LOG(Log::INF) << "Starting demo...";
    Log::initializeLogging(Log::INF);
    Mule::LogComponentLevels::initializeMule(Log::INF);

    try
    {

        std::string address = "asmemf-dro-02";
        std::string version = "2c";
        std::string community = "public";

        LOG(Log::INF) << "Opening connection";
        Snmp::SnmpBackend snmpBackend(address, version, community);

        std::string atcaRootOid = "1.3.6.1.4.1.16394.2.1.1";
        std::string boardPresent = atcaRootOid+ ".32.1.2";

        LOG(Log::INF) << "Start reading board presence";
        for (int boardNumber = 1 ; boardNumber <= 14 ; boardNumber++)
        {
            auto boardPresence = snmpBackend.snmpGetBoolean(boardPresent + "." + std::to_string(boardNumber));
            LOG(Log::INF) << "Acquired board " << boardNumber << " presence: " << std::boolalpha << (bool)boardPresence.second;
        }
        
        LOG(Log::INF) << "Start walking board presence";
        auto oids = snmpBackend.snmpDeviceWalk(boardPresent + ".0");

        LOG(Log::INF) << "Printing walked OIDs";
        for (auto oid: oids)
        {
            oid.printOidFromVector();
        }
        
    }
    catch (const std::exception &e)
    {
        LOG(Log::ERR) << "Caught: " << e.what();
    }
}





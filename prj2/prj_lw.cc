///////////////////////////////////////////////////
//
// CIS 549
//
//         Project #2 and Project #3
//
//////////////////////////////////////////////////

#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include <list>
#include <random>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ipv4-address.h"
//NetAnim
#include "ns3/netanim-module.h"
//WiFi
#include "ns3/wave-mac-helper.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wifi-module.h"
//LTE
#include "ns3/point-to-point-helper.h"
#include "ns3/lte-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/lte-module.h"
//Flow
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/socket.h"
#include "ns3/trace-helper.h"
#include "ns3/packet.h"
#include "ns3/virtual-net-device.h"

#define TCP_TEST 1
#define UDP_TEST 2

#define WIFI 1
#define LTE 2

#define SIMULATION_TIME_FORMAT(s) Seconds(s)
#define THROUGHPUT_MEASUREMENT_INTERVAL_MS 100.0  // 100 ms measurment interval

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("V2vExample");
std::string prefix_file_name = "CIS549";
int Scenario = 0;
uint16_t numberUE = 1;

// node image resource id
uint32_t serverImgId, routerImgId, pgwImgId, enbImgId, wifiapImgId, ueImgId;

vector<Ptr<OutputStreamWrapper>> throughputStream;
Ptr<OutputStreamWrapper> throughputAllDlStream;

vector<Ptr<PacketSink>> sink;
vector<uint64_t> lastTotalRx;


// #Function to Calulate Thoughput

void CalculateThroughput()
{
    double totalDlThroughput = 0.0;

    for (uint16_t i = 0; i < numberUE; i++) {
        Time now = Simulator::Now ();                                                
	// Return the simulator's virtual time.
        double cur = ((sink[i]->GetTotalRx() - lastTotalRx[i]) * (double) 8 / 1e6) * (1000.0 / THROUGHPUT_MEASUREMENT_INTERVAL_MS);  
	// Convert Application layer total RX Bytes to MBits.

        if (lastTotalRx[i] == 0) {cur = 0;}
        
	*throughputStream[i]->GetStream () << now.GetSeconds () << " " << cur << std::endl;
        lastTotalRx[i] = sink[i]->GetTotalRx ();
        totalDlThroughput += cur;
    }

    // all DL throughput measurement
    *throughputAllDlStream->GetStream ()  << Simulator::Now ().GetSeconds () << " " << totalDlThroughput << std::endl;

    Simulator::Schedule (MilliSeconds (THROUGHPUT_MEASUREMENT_INTERVAL_MS), &CalculateThroughput); // Measurement Interval THROUGHPUT_MEASUREMENT_INTERVAL_MS milliseconds
}


//==============================================================================//

int main(int argc, char *argv[]) {

    double simTime = 10;   // simulation time in sec
    numberUE = 1;
    int DataSizeforTCP = 20000;  // byte
    int Transport =  TCP_TEST;
    std::string DataRateforUDP = "100Mb/s";
    prefix_file_name = "CIS549";
    AsciiTraceHelper ascii;

    // this is the one way link delay between router and PGW
    // you may change this delay for RTT variation for LTE path
    int delayValueforLte = 20; // ms

    // this is the one way link delay between router and WiFi AP
    // you may change this delay for RTT variation for WIFI path
    int delayValueforWifi = 20; // ms


    // this is the one way link delay between router and SERVER
    // If you change this value, then both Wi-Fi and LTE path RTT will be affected
    int delayValueBtwnRemoteHostAndRouter = 20;   // ms

    // TCP buffer size configuration
    int tcpSendBufBytes = 10240000;   // bytes
    int tcpRcvBufBytes =  64000;  // TCP receive buffer size byte, default = 64000 Bytes

 
    // LTE Channel Bandwidth
    double chBwMHz = 20;   // LTE default channel Bandwidth=20 MHz (100 PRBs)
    // LTE bandwidth in terms oaf nuymber of PRB
    int lteTotalPRBcount = 100;   // reflect 20MHz


    // WIFI bandwidth
    int wifiChannelWidth = 40;   // default wife width (MHz)

    // if nStreams == 1 then phyRate can be up to HtMcs7
    // if nStreams == 2 then phyRate can be up to HtMcs15
    uint8_t nStreams = 1;    // wifi number of stream
    std::string phyRate = "HtMcs7";   // Wifi 802.11n MCS


    // This is where all parameters input at the command line are read into variables
    CommandLine cmd;
    cmd.AddValue ("simTime", "Simulation time in seconds (Default: 10 sec)", simTime);
    cmd.AddValue ("NumberUE", "Number of UEs (Default: 1 UE)", numberUE);
    cmd.AddValue ("Scenario", "Differnet Simulation Scenario", Scenario);
    cmd.AddValue ("DataSizeforTCP", "Total Data Size for TCP (Default = 20000)", DataSizeforTCP);
    cmd.AddValue ("Transport", "Transport Layer Protocol (TCP = 1, UDP = 2) (Default: TCP)", Transport);
    cmd.AddValue ("DataRateforUDP", "Data Rate for UDP (Defaule = 100Mb/s)", DataRateforUDP);
    cmd.AddValue ("OutputFileName", "The Prefix Output File Name (Default: CIS549)", prefix_file_name);

    // LTE channel Bandwidth options: 1.4 MHz, 5 MHz, 10 MHz, and 20 Mhz
    cmd.AddValue ("chBwMHz", "Select LTE Channel Bandwidth(Default: 20)", chBwMHz);

    //////////////////////////////////////
    // cis549: Project 2 : Problem 3
    // Add options as specified in the assignment sheet

    // EDIT START : a several lines of code

    cmd.AddValue ("wifiMcs", "HtMcs1 or HtMcs7 (This is for the Wi-Fi configuration)", phyRate);
    cmd.AddValue ("tcpRcvBufBytes", "TCP receive buffer size in bytes", tcpRcvBufBytes);
    cmd.AddValue ("delayValueforRHtoR", "one-way link delay in msec between the Remote Host(Server) and the Router", delayValueBtwnRemoteHostAndRouter);
    cmd.AddValue ("delayValueforWifi", "link delay in msec between the router and WiFi AP", delayValueforWifi); cmd.AddValue ("wifiMcs", "HtMcs1 or HtMcs7 (This is for the Wi-Fi configuration)", phyRate);
    cmd.AddValue ("tcpRcvBufBytes", "TCP receive buffer size in bytes", tcpRcvBufBytes);
    cmd.AddValue ("delayValueforRHtoR", "one-way link delay in msec between the Remote Host(Server) and the Router", delayValueBtwnRemoteHostAndRouter);
    cmd.AddValue ("delayValueforWifi", "link delay in msec between the router and WiFi AP", delayValueforWifi);

    // EDIT END

    cmd.Parse (argc, argv);

    uint16_t numberEnb = 1;
    uint16_t numberRemote = 1;

    switch ((int)(chBwMHz*10)) {
        case 200:
            lteTotalPRBcount=100;   // 20 MHz : 100 PRBs
            break;
        case 100:
            lteTotalPRBcount=50;   // 10 MHz : 50 PRBs
            break;
        case 50:
            lteTotalPRBcount=25;   // 5 MHz : 25 PRBs
            break;
        case 14:
            lteTotalPRBcount=6;   // 1.4 MHz : 6 PRBs
            break;
        default:
            cout << "Error: Incorrect value for chBwMHz option." << endl;
            cout << "Error: chBwMhz option can take only 1.4, 5, 10, or 20)"<< endl;
            exit(1);
            //break;  
    }

    Config::SetDefault("ns3::PointToPointEpcHelper::S1uLinkDelay", TimeValue (MilliSeconds (1.0)));  // delay between SGW and eNB
    // Configuration for LTE link                                               //
    Config::SetDefault("ns3::MacStatsCalculator::DlOutputFilename", StringValue(prefix_file_name + "-DlMacStat.dat"));
    Config::SetDefault("ns3::MacStatsCalculator::UlOutputFilename", StringValue(prefix_file_name + "-UlMacStat.dat"));
    Config::SetDefault("ns3::LteEnbNetDevice::DlBandwidth", UintegerValue(lteTotalPRBcount));
    Config::SetDefault("ns3::LteEnbNetDevice::UlBandwidth", UintegerValue(lteTotalPRBcount));
    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(20000000)); //AM/UM

    // Configuration for WiFi link
    Config::SetDefault("ns3::WifiMacQueue::MaxPacketNumber", UintegerValue(10000000));
    Config::SetDefault("ns3::WifiMacQueue::MaxDelay", TimeValue (MilliSeconds (1000.0)));

    // Transmission mode (SISO [0], MIMO [1])                                   //
    Config::SetDefault ("ns3::LteEnbRrc::DefaultTransmissionMode", UintegerValue (0));  // Do not change

    //cout << "lteTotalPRBcount=" << lteTotalPRBcount << "\n";

    ConfigStore inputConfig;
    inputConfig.ConfigureDefaults ();

    // Create the nodes in this simulation                                      //
    // Create node 0: server                                                    //
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create (numberRemote);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);

    // Create node 1: router                                                    //
    NodeContainer router;
    router.Create(1);

    // The initialization of PGW is inside the PointToPointEpcHelper            //
    // Create node 2: PGW                                                       //
    // Create node 3: Dummy node                                                //
    Ptr<LteHelper> lteHelper;
    Ptr<PointToPointEpcHelper> epcHelper;
    NodeContainer pgwContainer;
    if (Scenario == LTE) {
        // LTE only scenario
        lteHelper = CreateObject<LteHelper> ();
        epcHelper = CreateObject<PointToPointEpcHelper> ();
        lteHelper -> SetEpcHelper (epcHelper);
        lteHelper -> SetSchedulerType("ns3::RrFfMacScheduler");
        lteHelper -> SetAttribute ("PathlossModel", StringValue ("ns3::FriisPropagationLossModel"));
    }
    else if (Scenario == WIFI) {
        // Wi-Fi Only scenario
        pgwContainer.Create(1);
    }
    else
    {
        printf("ERROR: Scenario should be 1 for WIFI test or 2 for LTE test.\n");
        exit(1);
    }

    Ptr<Node> pgw;
    Ptr<Node> dummyNode;
    if (Scenario == LTE) {
        pgw = epcHelper->GetPgwNode ();
        dummyNode = epcHelper->GetSegwNode ();
    }
    else {
        pgw = pgwContainer.Get(0);
        dummyNode = pgwContainer.Get(1);
    }
    // Create node 4: enb                                                       //
    NodeContainer enbNodes;
    enbNodes.Create(numberEnb);
    // Create node 5: AP                                                        //
    NodeContainer apWiFiNode;
    apWiFiNode.Create(1);
    // Create node 6: UE                                                        //
    NodeContainer ueNodes;
    ueNodes.Create(numberUE);
    // Installing the Internet Stack for server, every UE, router, and WiFi AP  //
    InternetStackHelper internet;
    internet.Install (remoteHost);
    internet.Install(ueNodes);
    internet.Install(router);
    internet.Install(apWiFiNode);
    if (Scenario == WIFI) {
        internet.Install(pgw);
    }

    //////////////////////////////////////
    // cis549: Project 2 : Problem 1
    //
    // Set up mobility model for every node by (x,y,z), unit: meters            //
    // Mobility Model for UE                                                    //
    // use following 4 lines for the UE location boundary
    //
    //EDIT
    if (ueNodes.GetN() > 20) {
        printf("INPUT ERROR\n");
        exit(1);
    }
    double ueXmin = 1.0;
    double ueXmax = 8.0;
    double ueYmin = 12;
    double ueYmax = 30;

    // Generate a random number for X and Y coordination for each of UEs
    // in here using the above min and max boundary
    // (x, y, z) coordination for UE location. z=0 means ground
    //////////////////////////////////////
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> xDistribution(ueXmin, ueXmax);
    std::uniform_real_distribution<double> yDistribution(ueYmin, ueYmax);

    double tmpX;
    double tmpY;

    Ptr<ListPositionAllocator> positionAlloc1 = CreateObject<ListPositionAllocator> ();

    for (uint16_t i = 1; i <= ueNodes.GetN(); i++) {
        tmpX = xDistribution(gen);
        tmpY = yDistribution(gen);
        positionAlloc1->Add (Vector(tmpX, tmpY, 0));    // x, and y should be randomly generated
    }

    //EDIT END

    MobilityHelper mobilityUe;
    mobilityUe.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityUe.SetPositionAllocator(positionAlloc1);
    mobilityUe.Install (ueNodes);

    // Mobility Model for eNB
    Ptr<ListPositionAllocator> positionAlloc2 = CreateObject<ListPositionAllocator> ();
    positionAlloc2->Add (Vector(12, 12, 0));     // eNB position, this is used for animation positin as well

    MobilityHelper mobilityEnb;
    mobilityEnb.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityEnb.SetPositionAllocator(positionAlloc2);
    mobilityEnb.Install (enbNodes);

    // The location of server, router
    mobilityEnb.Install (remoteHost);
    mobilityEnb.Install (router);
    mobilityEnb.Install (dummyNode);

    // Mobility Model for WiFi AP
    Ptr<ListPositionAllocator> positionAlloc3 = CreateObject<ListPositionAllocator> ();
    positionAlloc3->Add (Vector(12, 28.2, 0));    // Wi-Fi AP position, this is used for animation positin as well

    MobilityHelper mobilityAP;
    mobilityAP.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityAP.SetPositionAllocator(positionAlloc3);
    mobilityAP.Install (apWiFiNode);

    // Install LTE Devices for User
    NetDeviceContainer enbLteDevs;
    NetDeviceContainer ueLteDevs;
    Ipv4InterfaceContainer ueIpIface;

    if (Scenario == LTE) {
        enbLteDevs = lteHelper->InstallEnbDevice (enbNodes);
        ueLteDevs = lteHelper->InstallUeDevice (ueNodes);
        ueIpIface = epcHelper->AssignUeIpv4Address (NetDeviceContainer (ueLteDevs));

        // Set up the IP for UE from LTE                                            //
        for (uint32_t u = 0; u < ueNodes.GetN(); ++u) {
            Ptr<Node> ueNode = ueNodes.Get (u);
            Ipv4StaticRoutingHelper ipv4RoutingHelper;
            Ptr<Ipv4StaticRouting> ueStaticRouting = ipv4RoutingHelper.GetStaticRouting (ueNode->GetObject<Ipv4> ());
            ueStaticRouting->AddNetworkRouteTo(Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 1);
            ueStaticRouting->AddNetworkRouteTo(Ipv4Address ("10.1.2.0"), Ipv4Mask ("255.255.255.0"), 1);
        }

        // Attach UE to LTE
        for (uint16_t i = 0; i < ueNodes.GetN(); i++) {
            lteHelper->Attach (ueLteDevs.Get(i), enbLteDevs.Get(0));
        }
    }
    else {}

    // Set up WiFi parameter
    // Use 802.11n in 5GHz
    WifiMacHelper wifiMac;
    WifiHelper wifiHelper;
    wifiHelper.SetStandard (WIFI_PHY_STANDARD_80211n_5GHZ);

    // Set up Legacy Channel                                                    //
    // The propagation loss model is Friis                                      //
    YansWifiChannelHelper wifiChannel ;
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5e9));

    // Setup the physical layer of WiFi                                         //
    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
    wifiPhy.SetChannel (wifiChannel.Create ());

    // In this version, the number of streams is set up by Tx/RxAntennas        //
    // You can manually set up the MCS level
    // The method of setting is HtMcs1->HtMcs15                                 //

    wifiPhy.Set ("TxAntennas", UintegerValue (nStreams));
    wifiPhy.Set ("RxAntennas", UintegerValue (nStreams));

    wifiHelper.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue (phyRate), "ControlMode", StringValue ("HtMcs0"));

    // Configure AP                                                             //
    Ssid ssid = Ssid ("network");
    wifiMac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid));
    NetDeviceContainer apDevice;
    apDevice = wifiHelper.Install (wifiPhy, wifiMac, apWiFiNode);

    // Configure STA                                                            //
    wifiMac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid));
    NetDeviceContainer staDevices;
    staDevices = wifiHelper.Install (wifiPhy, wifiMac, ueNodes);

    // Set wifi channel width
    Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (wifiChannelWidth));

    // Set up the IP address for this wifi network                              //
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase ("192.168.0.0", "255.255.255.0");
    Ipv4InterfaceContainer WiFiInterface = ipv4h.Assign(NetDeviceContainer(apDevice, staDevices));


//------------------------Connect them together---------------------------------//

    // Create a p2p link for the pgw and the router
    // Create a p2p link for the wifi AP and the router
    // Create a p2p link for the pgw and the wifi AP

    PointToPointHelper p2ph;

    // Create a p2p link for the server and the router
    p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
    p2ph.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (delayValueBtwnRemoteHostAndRouter)));
    NetDeviceContainer internetDevices1 = p2ph.Install (router.Get(0), remoteHost);

    p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
    p2ph.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (delayValueforLte)));
    NetDeviceContainer internetDevices2 = p2ph.Install (pgw, router.Get(0));

    p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
    p2ph.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (delayValueforWifi)));
    NetDeviceContainer internetDevices3 = p2ph.Install (apWiFiNode.Get(0), router.Get(0));

    p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
    p2ph.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (1)));
    NetDeviceContainer internetDevices4 = p2ph.Install (pgw, apWiFiNode.Get(0));


    // Set up the IP address for every p2p link
    // For simplicity, we assume every p2p link has it own subnet address
    // Setup IP address for every P2P link
    ipv4h.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer internetIpIfaces1;
    internetIpIfaces1 = ipv4h.Assign (internetDevices1);

    ipv4h.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer internetIpIfaces2;
    internetIpIfaces2 = ipv4h.Assign (internetDevices2);

    ipv4h.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer internetIpIfaces3;
    internetIpIfaces3 = ipv4h.Assign (internetDevices3);

    ipv4h.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer internetIpIfaces4;
    internetIpIfaces4 = ipv4h.Assign (internetDevices4);


    // Build up the static routing manually
    // Set up the routing table for the server
    if (Scenario == LTE) {
        Ipv4StaticRoutingHelper ipv4RoutingHelper;
        Ptr<Ipv4StaticRouting> remoteHostStaticRouting = ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());
        remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);
        remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("192.168.0.0"), Ipv4Mask ("255.255.255.0"), 1);

        // Set up the routing table for the router
        Ptr<Ipv4StaticRouting> routerStaticRouting = ipv4RoutingHelper.GetStaticRouting (router.Get(0)->GetObject<Ipv4> ());
        routerStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 2);
        // This is the routing entry when you need use wifi-only
        routerStaticRouting->AddNetworkRouteTo (Ipv4Address ("192.168.0.0"), Ipv4Mask ("255.255.255.0"), 3);
        routerStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 1);

        // Set up the routing table for the wifi
        Ptr<Ipv4StaticRouting> apStaticRouting = ipv4RoutingHelper.GetStaticRouting (apWiFiNode.Get(0)->GetObject<Ipv4> ());
        apStaticRouting->AddNetworkRouteTo(Ipv4Address ("10.1.3.0"), Ipv4Mask ("255.255.255.0"), 2);

        Ptr<Ipv4StaticRouting> staStaticRouting = ipv4RoutingHelper.GetStaticRouting (ueNodes.Get(0)->GetObject<Ipv4> ());
        staStaticRouting->AddNetworkRouteTo(Ipv4Address ("10.1.3.0"), Ipv4Mask ("255.255.255.0"), Ipv4Address("192.168.0.1"), 2);
        staStaticRouting->AddNetworkRouteTo(Ipv4Address ("192.168.0.0"), Ipv4Mask("255.255.0.0"), 2);

        // Set up the routing table for the P-GW
        // We force the packet to WiFi requiring to go to P-GW first
        Ptr<Ipv4StaticRouting> pgwStaticRouting = ipv4RoutingHelper.GetStaticRouting (pgw->GetObject<Ipv4> ());
        pgwStaticRouting->AddNetworkRouteTo(Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 3);
        pgwStaticRouting->AddNetworkRouteTo(Ipv4Address ("192.168.0.0"), Ipv4Mask ("255.255.255.0"), 4);

    }
    else if (Scenario == WIFI) {
        Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    }
    else
    {
        printf("ERROR: Scenario should be 1 for WIFI test or 2 for LTE test.\n");
        exit(1);
    }

//------------------------------------------------------------------------------//
    // Set up TCP application from the server to the user                       //
    // The MTU size is set up in SegmentSize                                    //
    // The maximum congestion window is set up in SndBufSize and RcvBufSize     //
    // This is a FTP download application with MaxBytes (arbitrary)             //

    double tcpAppStartTime = 1.0;

    for (uint16_t i = 0; i < ueNodes.GetN(); i++) {
        Ipv4Address DestAddr;
        if (Scenario == LTE) {
            DestAddr = ueIpIface.GetAddress(i);
        } else if (Scenario == WIFI) {
            DestAddr = WiFiInterface.GetAddress (i + 1);
        }
 
        if (Transport == TCP_TEST) {
            uint16_t port = 50000;
            Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));   // MSS size setting, don't need to change
            Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(tcpSendBufBytes));
            Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(tcpRcvBufBytes));   // Receiver buffer size

            Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
            PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
            AddressValue sinkAddress (InetSocketAddress (DestAddr, port));
            BulkSendHelper ftp ("ns3::TcpSocketFactory", Address ());
            ftp.SetAttribute ("Remote", sinkAddress);
            ftp.SetAttribute ("SendSize", UintegerValue (1400));   // don't need to change
            ftp.SetAttribute ("MaxBytes", UintegerValue (DataSizeforTCP)); // File size (Bytes)

            ApplicationContainer sourceApp = ftp.Install (remoteHost);
            sourceApp.Start (Seconds (tcpAppStartTime));
            sourceApp.Stop (Seconds (simTime));

            sinkHelper.SetAttribute ("Protocol", TypeIdValue (TcpSocketFactory::GetTypeId ()));
            ApplicationContainer sinkApp = sinkHelper.Install (ueNodes.Get(i));
            Ptr<PacketSink> sink_temp = StaticCast<PacketSink> (sinkApp.Get (0));
            sink.push_back(sink_temp);

            sinkApp.Start (Seconds (tcpAppStartTime));
            sinkApp.Stop (Seconds (simTime));
        }
        else if (Transport == UDP_TEST) {
            uint16_t port = 9;
            OnOffHelper onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress (DestAddr, port)));
            onoff.SetConstantRate (DataRate (DataRateforUDP));    // data transmission rate
            onoff.SetAttribute ("PacketSize", UintegerValue (1400));

            ApplicationContainer apps = onoff.Install (remoteHost);
            apps.Start (Seconds (1.0));
            apps.Stop (Seconds (simTime));

            // Create a packet sink to receive these packets
            PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory", Address (InetSocketAddress (Ipv4Address::GetAny (), port)));
            apps = sinkHelper.Install (ueNodes.Get(i));
            Ptr<PacketSink> sink_temp = StaticCast<PacketSink> (apps.Get(0));
            sink.push_back(sink_temp);
            apps.Start (Seconds (1.0));
            apps.Stop (Seconds (simTime));
        }
        else
        {
            printf("ERROR: Transport should be 1 for TCP test or 2 for UDP test.\n");
            exit(1);
        }
    }


    //------------------------------------------------------------------------------//
    /////////////////////////////////////////////////////////////////////////
    // cis 549 Project 2 - Problem 2
    // Add your code to capture packets at the specified network elements in the assignment sheet
    // This will generate pcap file, and the Wireshark can open this pcap file for the analysis.
    // The network node and interface index are provided in the assignment sheet

    // EDIT START ( about several lines of codes)

    internet.EnablePcapIpv4("server-to-router", 0, 1, false);
    internet.EnablePcapIpv4("router-to-wifi-ap", 1, 3, false);
    internet.EnablePcapIpv4("router-to-server", 1, 1, false);

    // EDIT END
  
    // Animation Setup in this part                                             //
    // SetConstantPosision is used to set up the position for every node        //
    // UpdateNodeDescription is used to set up the name for every node          //
    // UpdateNodeColor is used to set up the color for every node               //
    // "DO NOT" set up the poistions after calling anim("document_name")        //

    AnimationInterface::SetConstantPosition (remoteHost, 45.0, 20);
    AnimationInterface::SetConstantPosition (router.Get(0), 33.75, 20);
    AnimationInterface::SetConstantPosition (pgw, 28.2, 12);
    AnimationInterface anim (prefix_file_name + "-animation.xml");


    ///////////////////////////////////////////////
    // The image file must be stored in this path
    //
    serverImgId = anim.AddResource ("/home/cis549/Downloads/server.png");
    routerImgId = anim.AddResource ("/home/cis549/Downloads/router.png");
    pgwImgId = anim.AddResource ("/home/cis549/Downloads/pgw.png");
    enbImgId = anim.AddResource ("/home/cis549/Downloads/enb.png");
    wifiapImgId = anim.AddResource ("/home/cis549/Downloads/wifiap.png");
    ueImgId = anim.AddResource ("/home/cis549/Downloads/ue.png");

    // set node image
    anim.UpdateNodeImage(remoteHost->GetId (), serverImgId );
    anim.UpdateNodeImage(router.Get(0)->GetId (), routerImgId );
    anim.UpdateNodeImage(pgw->GetId (), pgwImgId );
    anim.UpdateNodeImage(enbNodes.Get(0)->GetId (), enbImgId );
    anim.UpdateNodeImage(apWiFiNode.Get(0)->GetId (), wifiapImgId );

    // set node image size
    double nodeImageSize = 4;
    anim.UpdateNodeSize(remoteHost->GetId (), nodeImageSize * 1.5, nodeImageSize * 0.5 );
    anim.UpdateNodeSize(router.Get(0)->GetId (), nodeImageSize * 0.8, nodeImageSize * 0.8 );
    anim.UpdateNodeSize(pgw->GetId (), nodeImageSize, nodeImageSize );
    anim.UpdateNodeSize(enbNodes.Get(0)->GetId (), nodeImageSize * 1.4, nodeImageSize * 1.4);
    anim.UpdateNodeSize(apWiFiNode.Get(0)->GetId (), nodeImageSize * 1.5, nodeImageSize * 1.5 );

    ///////////////////////////////
    anim.UpdateNodeDescription (enbNodes.Get (0), "eNB");
    anim.UpdateNodeDescription (apWiFiNode.Get (0), "WiFi AP");
    anim.UpdateNodeDescription (remoteHost, "Server");
    for (uint16_t i = 0; i < ueNodes.GetN(); i++) {
        anim.UpdateNodeDescription (ueNodes.Get(i), "user" + to_string(i));
        anim.UpdateNodeImage(ueNodes.Get(i)->GetId(), ueImgId );
        anim.UpdateNodeSize(ueNodes.Get(i)->GetId (), nodeImageSize, nodeImageSize );
    }
    anim.UpdateNodeDescription (router.Get(0), "Router");
    anim.UpdateNodeDescription (pgw, "PGW");

    ///////////////////////////////////////////////////////////////////
    // throughput measurement
    AsciiTraceHelper ascii_throughput;
    for (uint16_t i = 0; i < ueNodes.GetN(); i++) {
        Ptr<OutputStreamWrapper> throughputStream_temp = ascii.CreateFileStream ((prefix_file_name + "-throughput-ue" + to_string(i + 1) + ".dat").c_str ());
        throughputStream.push_back(throughputStream_temp);
        int lastTotalRx_temp = 0;
        lastTotalRx.push_back(lastTotalRx_temp);
    }

    // all throughput measurment file
    throughputAllDlStream = ascii.CreateFileStream ((prefix_file_name + "-throughput-ue-all" + ".dat").c_str ());

    // User downlink thrughput measurment (bps)
    Simulator::Schedule (Seconds (0.1), &CalculateThroughput);
    ////////////////////////////////////////////////////////////////////

    // Setup LTE MAC trace file
    if (Scenario == LTE) {
        lteHelper->EnableMacTraces ();
    }

//---------------------- Simulation Stopping Time ------------------------------//
    Simulator::Stop(SIMULATION_TIME_FORMAT(simTime));
//------------------------------------------------------------------------------//

//--------------------------- Simulation Run -----------------------------------//
    Simulator::Run();

    Simulator::Destroy();
//----------------------------------------------------------------------//
    return EXIT_SUCCESS;
}

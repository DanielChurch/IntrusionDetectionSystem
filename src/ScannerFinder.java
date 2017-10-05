/*
 * Daniel Church
 * Assignment 4
 * 3/2/17
 */

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class ScannerFinder {

	Map<String, Integer> syn = new HashMap <String, Integer>();
	Map<String, Integer> syn_ack = new HashMap <String, Integer>();
	
	public ScannerFinder(final String path) {
		final StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(path, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
		
		//Read through all packets
		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

			final Tcp tcp = new Tcp();
			final Ip4 ip = new Ip4();

			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				if (packet.hasHeader(tcp) && packet.hasHeader(ip) && tcp.flags_SYN() && tcp.flags_ACK()) { //The packet is SYN ACK
					//Increment the destinations ip's SYN ACK count
					String synackip = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
					if(syn_ack.containsKey(synackip))
						syn_ack.put(synackip, syn_ack.get(synackip)+1);
					else
						syn_ack.put(synackip, 1);
				}else if(packet.hasHeader(tcp) && packet.hasHeader(ip) && tcp.flags_SYN()){ //The Packet is just SYN
					//Increment the source ip's SYN count
					String synip = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
					if(syn.containsKey(synip))
						syn.put(synip, syn.get(synip)+1);
					else
						syn.put(synip, 1);
				}
			}

		}, errbuf);
		pcap.close();
		
		for(String ssyn : syn.keySet()) //For all IP's that sent SYN
			if(syn_ack.containsKey(ssyn)) { //Check if there are any SYN ACK packets sent to that IP
				if(syn.get(ssyn) > 3*syn_ack.get(ssyn)) //# of SYN Packets > 3 * # of SYN ACK Packets
					System.out.println(ssyn);
			}else //The server didn't respond - # of SYN Packet > 0 by default
				System.out.println(ssyn);
	}

	public static void main(String[] args) {
		new ScannerFinder(args[0]);
	}

}

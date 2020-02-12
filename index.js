const pcap = require("pcap");
const tcp_tracker = new pcap.TCPTracker();
const pcap_session = pcap.createSession("en0", "ip proto \\tcp");
const chalk = require("chalk");

const getSourceAndDestIPAddress = packet => {
  const src = packet.payload.payload.saddr.addr;
  const srcPort = packet.payload.payload.payload.sport;
  const dest = packet.payload.payload.daddr.addr;
  const destPort = packet.payload.payload.payload.dport;
  return {
    src: src.join("."),
    srcPort,
    dest: dest.join("."),
    destPort
  };
};

const getPayloadData = packet => {
  const data = packet.payload.payload.payload.data;
  const length = packet.payload.payload.payload.dataLength;
  if (data !== null) {
    return {
      data: data,
      length
    };
  }
  return {
    data: null,
    length: 0
  };
};

const getTTL = packet => packet.payload.payload.ttl;

const getSequence = packet => packet.payload.payload.payload.seqno;

const getAck = packet => packet.payload.payload.payload.ackno;

const getTimeStamp = packet => packet.payload.payload.payload.options.timestamp;

const getCheckSum = packet => packet.payload.payload.headerChecksum;

const isMoreFragment = packet => packet.payload.payload.flags.moreFragments;
pcap_session.on("packet", function(raw_packet) {
  const packet = pcap.decode.packet(raw_packet);
  const { src, dest, srcPort, destPort } = getSourceAndDestIPAddress(packet);
  const { data, length } = getPayloadData(packet);
  const sequenceNumber = getSequence(packet);
  const ackNumber = getAck(packet);
  const timeStamp = getTimeStamp(packet);
  const checksum = getCheckSum(packet);
  console.log(chalk.bold(chalk.green("new Packat arrive")));
  console.log(chalk.hex("#795548")(`Date Time: ${new Date(timeStamp)}`));
  console.log(chalk.blue(`ttl: ${getTTL(packet)}`));
  console.log(chalk.yellow(`Source IP address: ${src}:${srcPort}`));
  console.log(chalk.yellow(`Destination IP address: ${dest}:${destPort}`));
  console.log(chalk.green(`more fragment: ${isMoreFragment(packet)}`));
  console.log(chalk.hex("#f9a825")(`Sequence Number: ${sequenceNumber}`));
  console.log(chalk.hex("#f9a825")(`Acknowledgement Number: ${ackNumber}`));
  console.log(chalk.hex("#ffc107")(`checksum: ${checksum}`));
  console.log(chalk.cyan(`Data: ${data}`));
  console.log(chalk.cyan(`Data Length: ${length}`));
  console.log("\n\n");
});

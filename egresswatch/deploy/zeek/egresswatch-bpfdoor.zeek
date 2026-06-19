##! egresswatch — Zeek policy for the documented BPFDoor magic-packet markers.
##!
##! egresswatch SHIPS this script; it does NOT install Zeek or load it. Drop it in
##! your Zeek site policy (e.g. @load it from local.zeek) on a tap/mirror sensor
##! at the homelab gateway. See deploy/README.md.
##!
##! Markers detected:
##!   1) The magic-packet activation frame's hardcoded TCP sequence number 1234.
##!   2) The heartbeat thread's technically invalid ICMP Echo with code 1.
##!
##! Zeek raises a notice on each; route notices to the same collector as the
##! egresswatch JSON reports.

@load base/frameworks/notice

module EgresswatchBPFDoor;

export {
    redef enum Notice::Type += {
        ## A TCP packet carried the hardcoded BPFDoor magic sequence number 1234.
        Magic_Seq_1234,
        ## An ICMP Echo carried the anomalous code 1 used by the BPFDoor heartbeat.
        Invalid_ICMP_Code1,
    };

    ## The hardcoded magic sequence number BPFDoor looks for in its activation
    ## packet. Redefine in local.zeek if you track a variant using another value.
    const magic_seq: count = 1234 &redef;
}

# Inspect raw packets so we can read the TCP sequence number and the ICMP code,
# which are not surfaced on the connection-level events. raw_packet gives the L2+
# header info Zeek parsed for this packet.
event raw_packet(p: raw_pkt_hdr)
{
    # --- Marker 1: TCP sequence == magic_seq (1234) ---
    if ( p?$tcp && p$tcp$seq == magic_seq )
    {
        local cid = fmt("%s:%d -> %s:%d",
            p$ip$src, p$tcp$sport, p$ip$dst, p$tcp$dport);
        NOTICE([$note=Magic_Seq_1234,
                $msg=fmt("BPFDoor magic-packet TCP seq=%d (activation trigger)", magic_seq),
                $sub=cid]);
    }

    # --- Marker 2: ICMP Echo (type 0/8) with invalid code 1 ---
    if ( p?$icmp && (p$icmp$itype == 8 || p$icmp$itype == 0) && p$icmp$icode == 1 )
    {
        local who = "";
        if ( p?$ip )
            who = fmt("%s -> %s", p$ip$src, p$ip$dst);
        else if ( p?$ip6 )
            who = fmt("%s -> %s", p$ip6$src, p$ip6$dst);
        NOTICE([$note=Invalid_ICMP_Code1,
                $msg=fmt("BPFDoor heartbeat — ICMP echo type=%d invalid code=1", p$icmp$itype),
                $sub=who]);
    }
}

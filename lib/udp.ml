(*
 * Copyright (c) 2010-2014 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

module Make(Ip: V1_LWT.IP) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ip = Ip.t
  type ipaddr = Ip.ipaddr
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
  ]

  type t = {
    ip : Ip.t;
  }

  let id {ip} = ip


  let respond_u1 ~src ~dst ~src_port t bufs =
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`ICMP in
    let frame = Cstruct.set_len frame header_len in
    Ip.writev t.ip frame []

(*
(* HERE - Respond to nmap's U1 probe
    Look at ipv4.ml - icmp_input function
    May wish to call this
 *)
  let respond_u1 ~source_port ~dest_ip ~dest_port t bufs =
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`UDP in
    let frame = Cstruct.set_len frame (header_len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame header_len in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_bug dest_port;
(* HERE - IPL - Modify to add up to 0xB0 = 176 bytes *)
(*    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + Cstruct.lenv bufs);  *)
(* Have header_len = IP header length, sizeof_udp *)
    let data_len = 176 - Wire_structs.Ipv4_wire.sizeof_ipv4 - Wire_structs.sizeof_udp in
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + data_len);
(* HERE - Need to truncate bufs to data_len *)
    let csum = Ip.checksum frame (udp_buf :: bufs) in
    Wire_structs.set_udp_checksum udp_buf csum;
    Ip.writev t.ip frame bufs
(* HERE - Need to handle ICMP echo reply code value set to zero = 0 *)
(* HERE - Need to handle ICMP port unreachable header's last four bytes being zero;
    it's 8 bytes long *)
*)

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None   -> Lwt.fail (Failure "TODO; random source port")
      | Some p -> Lwt.return p
    end >>= fun source_port ->
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`UDP in
    let frame = Cstruct.set_len frame (header_len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame header_len in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_buf dest_port;
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + Cstruct.lenv bufs);
    (* Wire_structs.set_udp_checksum udp_buf 0; *)
    let csum = Ip.checksum frame (udp_buf :: bufs) in
    Wire_structs.set_udp_checksum udp_buf csum;
    Ip.writev t.ip frame bufs

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  (* FIXME: [t] is not taken into account at all? *)
  let input ~listeners _t ~src ~dst buf =
    let dst_port = Wire_structs.get_udp_dest_port buf in
    let data =
      Cstruct.sub buf Wire_structs.sizeof_udp
        (Wire_structs.get_udp_length buf - Wire_structs.sizeof_udp)
    in
(*    Printf.printf "UDP: Returning unit\n";
    Lwt.return_unit  *)
    match listeners ~dst_port with
(* HERE - U1 - Respond on closed port with None *)
(*    | None    -> Lwt.return_unit    *)
    | None    ->
      let src_port = Wire_structs.get_udp_source_port buf in
      respond_u1 ~src ~dst ~src_port t bufs
(*            write ~source_port:dst_port ~dest_ip:src ~dest_port:src_port _t data *)
    | Some fn ->
      let src_port = Wire_structs.get_udp_source_port buf in
      fn ~src ~dst ~src_port data

  let connect ip = Lwt.return (`Ok { ip })

  let disconnect _ = Lwt.return_unit
end

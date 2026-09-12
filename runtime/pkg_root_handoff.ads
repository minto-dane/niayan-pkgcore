-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization; with System;
with MC_Types; use MC_Types;
package Pkg_Root_Handoff with SPARK_Mode => Off is
   type Session is new Ada.Finalization.Limited_Controlled with private;
   procedure Open (C : in out Session; Supervisor_FD : Integer; Deadline : Counter; Status : out Outcome);
   procedure Prepare (C : in out Session; Generation, Root_Manifest, Archive, Worker : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome);
   procedure Close (C : in out Session);
   overriding procedure Finalize (C : in out Session);
   -- Internal nonroot worker channel; not a public socket or execution permit.
   -- The root launcher creates a seqpacket pair with SO_PASSCRED enabled on
   -- both ends BEFORE spawning the worker, then passes the private child FD.
   -- Open borrows that FD and pins the actual root peer with SO_PEERPIDFD.
   -- Prepare performs one attempt per Session and transfers borrowed archive
   -- and native CAS OFDs. Use with Generation_Stage.Prepare_Root so the
   -- mandatory native checks and stage/root/CAS reservations surround it.
   -- The supervisor independently admits the exact 192-byte scope and checks
   -- current operator/supply/consent before its root session request and reply.
   -- A matching acknowledgment means prepared only, not published or booted.
   -- It does not independently observe a root inode or authorize reinspection.
   -- Any failure after attempted delivery is Indeterminate. No reconnect or
   -- retry, deadline renewal, serialized grant, or change to the borrowed FDs.
   -- The caller retains the original channel for the supervisor's full physical
   -- exclusion lifetime. Close only releases this duplicate; it does not prove
   -- remote cleanup. Single owning process/task; fork copies cannot send.
private
   type Session is new Ada.Finalization.Limited_Controlled with record
      Handle : System.Address := System.Null_Address;
   end record;
end Pkg_Root_Handoff;

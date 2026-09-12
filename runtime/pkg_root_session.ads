-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization; with System;
with MC_Types; use MC_Types;
with Pkg_Root_Preparation;
package Pkg_Root_Session with SPARK_Mode => Off is
   type Session is new Ada.Finalization.Limited_Controlled with private;
   procedure Open
     (C : in out Session; Socket_Path, Boot_ID : String;
      Generation, Root_Manifest, Archive, Worker, Device_Plan : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Bank : Pkg_Root_Preparation.Root_Identity;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome);
   procedure Observe
     (C : in out Session; Archive_FD, Reservation_FD : Integer; Status : out Outcome);
   function Held (C : Session) return Boolean;
   function Observation (C : Session) return Pkg_Root_Preparation.Root_Identity;
   procedure Close (C : in out Session; Status : out Outcome);
   overriding procedure Finalize (C : in out Session);
   -- Internal ROOT supervisor transport, distinct from the unprivileged stage
   -- SDK. Does not lift that SDK's UID checks or grant site/consent admission.
   -- Caller supplies independently authorized scope, boot/device/worker pins
   -- and borrowed actual native CAS/archive FDs; this API never unlocks them.
   -- Open keeps one connection until Close. In-use Open returns Conflict.
   -- Observe uses new borrowed FDs; no deadline renewal, reconnect or retry.
   -- Any failure after attempted delivery is Indeterminate, not non-execution.
   -- Held is local validity/expiry/connection status, not an independent mount
   -- observation or authorization. Observation is the server's root identity;
   -- its inode must be independently checked while supervisor exclusion holds
   -- before using it with the native generation observer. It is not boot proof.
   -- Failed Observe invalidates evidence but keeps the socket until Close.
   -- Close OK means controller EOF after its own cleanup, not success of the
   -- extraction, publication, all-writer exclusion or supervisor FD cleanup.
   -- Finalize only disconnects; it never waits or reports remote cleanup.
   -- Single owning process/task. Fork copies cannot operate the parent session.
private
   type Session is new Ada.Finalization.Limited_Controlled with record
      Handle : System.Address := System.Null_Address;
      Root : Pkg_Root_Preparation.Root_Identity;
   end record;
end Pkg_Root_Session;

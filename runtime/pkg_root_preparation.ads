-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Root_Preparation with SPARK_Mode => Off is
   type Root_Identity is record
      Mount_ID, Inode : Wide := 0;
      Device_Major, Device_Minor : Word := 0;
   end record;
   procedure Reinspect
     (Socket_Path : String; Generation, Root_Manifest, Archive, Worker : Digest;
      Stage : Identity; Size, Entries, Original_Deadline, Deadline : Counter;
      Expected_Root : Root_Identity; Archive_FD, Reservation_FD : Integer; Status : out Outcome);
   -- Expected_Root comes from an independent controller holding all-writer and
   -- mount exclusion, never from this service response. Original_Deadline is
   -- the saved extraction request's deadline, not a renewed authorization.
   -- Compare the complete response, including the original intent digest and
   -- fresh observation deadline. OK is a current observation only, not boot.
   procedure Request
     (Socket_Path : String; Generation, Root_Manifest, Archive, Worker : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome);
   -- Internal transport to the root-owned preparation service. Worker is the
   -- independently configured executable hash, not a value from its response.
   -- Caller holds stage/root/store reservations and verifies admission before
   -- and after this call. Success means extracted only, never published/booted.
   -- No retry after a packet may have been delivered. An uncertain result can
   -- leave a prepared or partial private root; inspect/recovery is separate.
end Pkg_Root_Preparation;

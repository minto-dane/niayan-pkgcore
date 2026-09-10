-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Receiver_Ledger with SPARK_Mode => Off is
   type Receipt_State is (Not_Recorded, In_Progress, Terminal_OK, Terminal_Failure);
   type Receipt is record
      State : Receipt_State := Not_Recorded;
      Request_ID : Identity := Zero_Identity;
      Envelope_Digest, Record_Digest : Digest := Zero_Digest;
      Sequence : Counter := 0;
      Result : Outcome := Indeterminate;
      Raw_Record : Bytes(1..256) := (others => 0);
   end record;
   procedure Provision (Policy_Directory, Parent_Directory, New_Name : String;
                        Status : out Outcome);
   -- Offline bootstrap ONLY: creates a new private subdirectory, never opens an
   -- existing directory for initialization. A failed provisioning is not retried
   -- by deleting evidence. Protected parent and independent lifecycle records
   -- are required; this does not resist a privileged whole-volume rollback.
   procedure Observe (Ledger_Directory : String; Root_ID, Request_ID : Identity;
                      Expected_Envelope : Digest; Value : out Receipt;
                      Status : out Outcome);
   -- Does not create, truncate, finish or replay a request. A nonempty, valid
   -- ledger is mandatory. It uses the receiver lock; busy is NOT absence.
   -- Terminal_Failure is not proof of no external effects.
end MC_Receiver_Ledger;

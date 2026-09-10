-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Pkg_Transactions;
package Pkg_Journal with SPARK_Mode, Pure is
   Record_Size : constant := 256;
   subtype Encoded_Record is Bytes (1 .. Record_Size);
   type Log_Record is record
      Sequence_Number : Counter := 0;
      Membership_Epoch : Counter := 0;
      Fence_Token : Counter := 0;
      Transaction_ID : Identity := Zero_Identity;
      Current : Pkg_Transactions.Phase := Pkg_Transactions.Empty;
      Plan : Digest := Zero_Digest;
      Previous : Digest := Zero_Digest;
      Before_Image : Digest := Zero_Digest;
      After_Image : Digest := Zero_Digest;
      Root_ID : Identity := Zero_Identity;
      Recorded_At : Counter := 0;
   end record;
   type Head is record
      Sequence_Number : Counter := 0;
      Membership_Epoch : Counter := 0;
      Fence_Token : Counter := 0;
      Last_Digest : Digest := Zero_Digest;
      Root_ID : Identity := Zero_Identity;
   end record;
   function Encode (Value : Log_Record) return Encoded_Record with Global => null;
   procedure Decode (Data : Bytes; Value : out Log_Record; Status : out Outcome)
     with Global => null;
   procedure Extend
     (State : in out Head; Value : Log_Record; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then State = State'Old)
         and then (if Status = OK then State.Sequence_Number > State'Old.Sequence_Number
           and then State.Root_ID = State'Old.Root_ID);
   -- Hash chaining detects accidental corruption. It does not authenticate a writer
   -- or prevent suffix truncation without an independent authenticated head anchor.
end Pkg_Journal;

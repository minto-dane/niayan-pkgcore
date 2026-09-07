-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Protocol with SPARK_Mode, Pure is
   Major : constant := 2;
   Minor : constant := 0;
   Header_Size : constant := 160;
   subtype Frame_Header is Bytes (1 .. Header_Size);
   type Message_Kind is
     (Plan_Request, Plan_Result, Prepare_Request, Prepared_Result,
      Apply_Request, Applied_Result, Inspect_Request, Inspect_Result,
      Recover_Request, Recover_Result, Contract_Hello, Contract_Result,
      Commit_Request, Commit_Result, Restore_Request, Restore_Result,
      Reconcile_Request, Reconcile_Result, Repair_Request, Repair_Result);
   type Header is record
      Version_Major : Natural range 0 .. 65_535 := Major;
      Version_Minor : Natural range 0 .. 65_535 := Minor;
      Kind : Message_Kind := Inspect_Request;
      Body_Length : Natural range 0 .. Max_Message := 0;
      Request_ID : Identity := Zero_Identity;
      Cluster_ID : Identity := Zero_Identity;
      Node_ID : Identity := Zero_Identity;
      Resource_ID : Identity := Zero_Identity;
      Membership_Epoch : Counter := 0;
      Fence_Token : Counter := 0;
      Sequence_Number : Counter := 0;
      Deadline : Counter := 0;
      Boot_ID : Identity := Zero_Identity;
      Body_Digest : Digest := Zero_Digest;
   end record;
   function Encode (Value : Header) return Frame_Header with Global => null;
   procedure Decode (Data : Bytes; Value : out Header; Status : out Outcome)
     with Global => null,
       Post => (if Status = OK then Value.Version_Major = Major
                 and then Value.Version_Minor = Minor);
   function Valid_Identity (Value : Header) return Boolean with Global => null;
end MC_Protocol;

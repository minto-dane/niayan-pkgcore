-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text;
package Pkg_File_Plan with SPARK_Mode, Pure is
   Max_Changes : constant := 1_024;
   Max_Plan_Bytes : constant := 4_500_000;
   type Kind is (Absent, Regular, Directory, Symbolic_Link);
   type Shape is record
      Node_Kind : Kind := Absent;
      Mode, UID, GID : Word := 0;
      Size, Mtime_Sec : Counter := 0;
      Mtime_Nsec : Natural range 0..999_999_999 := 0;
      Content, Xattrs : Digest := Zero_Digest;
   end record;
   type State_Domain is (Packaged_Files, Managed_Configuration, Business_Data,
                         Secrets, Audit_Data, Trust_State);
   type Change is record
      Path : MC_Text.Value;
      Domain : State_Domain := Packaged_Files;
      Before, After : Shape;
   end record;
   type Change_Array is array(Positive range 1..Max_Changes) of Change;
   type Plan is record
      Root_ID, Transaction_ID : Identity := Zero_Identity;
      Base_Generation, Target_Generation, Epoch, Fence : Counter := 0;
      Package_Set, Effect_Contract : Digest := Zero_Digest;
      Count : Natural range 0..Max_Changes := 0;
      Changes : Change_Array;
   end record;
   procedure Clear(P : out Plan) with Global=>null, Post=>P.Count=0;
   Shape_Size : constant := 128;
   Header_Size : constant := 192;
   subtype Encoded_Shape is Bytes(1..Shape_Size);
   function Valid(S : Shape) return Boolean with Global=>null;
   function Allowed_Path(Path : String) return Boolean with Global=>null;
   function Layout_Valid(P : Plan) return Boolean with Global=>null;
   function Equal(A, B : Shape) return Boolean with Global=>null;
   function Encode(S : Shape) return Encoded_Shape with Global=>null;
   procedure Decode_Shape(B : Bytes; S : out Shape; Status : out Outcome) with Global=>null;
   procedure Encode(P : Plan; B : out Bytes; Used : out Natural; Status : out Outcome) with Global=>null,
     Post => Used<=B'Length;
   procedure Decode(B : Bytes; P : out Plan; Status : out Outcome) with Global=>null;
   -- Exact preimage and postimage. Config changes are explicitly approved preimages,
   -- never an implicit overwrite of local edits. Data, secrets, audit and trust state
   -- are excluded. The schema is not a proof of arbitrary RPM script semantics.
end Pkg_File_Plan;

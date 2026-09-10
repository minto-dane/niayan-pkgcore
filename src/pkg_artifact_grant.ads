-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Text;
package Pkg_Artifact_Grant with SPARK_Mode, Pure is
   type Grant is record
      Repository : Identity:=Zero_Identity;
      Object, Snapshot, Contract : Digest:=Zero_Digest;
      Revision, Issued, Expires, Size : Counter:=0;
      URL : MC_Text.Value;
   end record;
   Maximum_Size : constant:=4_256;
   procedure Encode(G : Grant; B : out Bytes; Used : out Natural; Status : out Outcome) with Global=>null;
   procedure Decode(B : Bytes; G : out Grant; Status : out Outcome) with Global=>null;
   -- Authenticated overlay, not a claim upstream publishes TUF or has reproducible
   -- builds. Native RPM signatures are still required separately before staging.
end Pkg_Artifact_Grant;

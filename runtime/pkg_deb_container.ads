-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Text; with MC_Store;
package Pkg_Deb_Container with SPARK_Mode => Off is
   Max_Members : constant := 16;
   Max_Container : constant Counter := MC_Store.Max_Object_Size;
   Max_Control : constant Counter := 16 * 1024 * 1024;
   type Member_Kind is (Version_Info, Control_Archive, Data_Archive, Extension);
   type Compression is (Uncompressed, Gzip, XZ, Zstd, Bzip2, LZMA);
   type Member is record
      Name : MC_Text.Value;
      Kind : Member_Kind := Extension;
      Codec : Compression := Uncompressed;
      Offset, Length : Counter := 0;
      Content, Header : Digest := Zero_Digest;
   end record;
   type Member_Array is array (Positive range 1 .. Max_Members) of Member;
   type Envelope is record
      Original : Digest := Zero_Digest;
      Size : Counter := 0;
      Minor_Version : Counter := 0;
      Count, Control_Index, Data_Index : Natural range 0 .. Max_Members := 0;
      Items : Member_Array;
   end record;
   procedure Inspect (Store : MC_Store.Store; Original : Digest; Deadline : Counter;
                      Result : out Envelope; Status : out Outcome);
   procedure Stage_Member (Store : in out MC_Store.Store; Expected : Envelope;
                          Index : Positive; Deadline : Counter;
                          Content : out Digest; Status : out Outcome);
   -- Internal unprivileged reader and CAS ingestion, never root extraction.
   -- The complete original object is independently rehashed by MC_Store.
   -- Inspect validates the ar envelope and hashes exact compressed member bytes.
   -- It does NOT validate/decompress tar, control semantics, dependencies, effects,
   -- archive signatures, trust, or installation authority. No handler execution.
   -- Stage_Member reparses the original and compares the entire envelope before
   -- streaming a member to the existing CAS; caller offsets are never trusted.
   -- Extensions remain bound and can be retained as objects, not discarded.
   -- Resource scope / process deadline is also required: Open_Object's initial
   -- whole-object verification is not interruptible by this reader's deadline.
end Pkg_Deb_Container;

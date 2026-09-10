-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with Pkg_Deb_Semantics;
package Pkg_Deb_Fields with SPARK_Mode => Off is
   Max_Control : constant := 16 * 1024 * 1024;
   Max_Line : constant := 65_536;
   Max_Fields : constant := 256;
   type Document is private;
   type Value_Layout is (Raw_Field, Simple, Folded, Multiline);
   type Metadata is record
      Name, Version, Architecture, Source_Name, Source_Version : MC_Text.Value;
      Multi : Pkg_Deb_Semantics.Multi_Arch := Pkg_Deb_Semantics.No;
      Essential, Protected_Package, Has_Installed_Size : Boolean := False;
      Installed_Size_KiB : Counter := 0;
   end record;
   procedure Parse (Raw : Bytes; Result : out Document; Status : out Outcome);
   function Field_Count (Parsed : Document) return Natural;
   function Field_Name (Parsed : Document; Index : Positive) return String;
   function Content_Hash (Parsed : Document) return Digest;
   function Has_Field (Parsed : Document; Name : String) return Boolean;
   procedure Read_Value (Raw : Bytes; Parsed : Document; Name : String;
                         Layout : Value_Layout; Value : out Bytes;
                         Used : out Natural; Status : out Outcome);
   procedure Check_Identity (Raw : Bytes; Parsed : Document;
                             Result : out Metadata; Status : out Outcome);
   -- One binary-control stanza, strict UTF-8, case-insensitive field names and
   -- no empty values. Private offsets remain bound to the complete raw hash.
   -- Unknown fields remain addressable; no rewriting of the original occurs.
   -- Read_Value fails instead of truncating. Simple fields cannot be folded.
   -- Identity checks name/version/architecture label, Source, Multi-Arch,
   -- Essential/Protected and Installed-Size, plus presence and layout of the
   -- mandatory Maintainer/Description. It does not authenticate an email address,
   -- validate all optional fields, dependencies, effects or installation policy.
private
   type Field is record
      Name : MC_Text.Value;
      First, Last : Natural range 0 .. Max_Control := 0;
      Continuations : Natural := 0;
   end record;
   type Field_Array is array (Positive range 1 .. Max_Fields) of Field;
   type Document is record
      Hash : Digest := Zero_Digest;
      Size : Natural range 0 .. Max_Control := 0;
      Count : Natural range 0 .. Max_Fields := 0;
      Fields : Field_Array;
   end record;
end Pkg_Deb_Fields;

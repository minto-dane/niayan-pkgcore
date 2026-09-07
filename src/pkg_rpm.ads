-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_RPM with SPARK_Mode, Pure is
   Max_Header_Bytes : constant := 16_777_216;
   Max_Entries : constant := 4_096;
   type Index_Entry is record
      Tag : Word := 0;
      Data_Type : Natural range 0 .. 9 := 0;
      Data_Offset : Natural := 0; -- absolute, zero-based file offset
      Item_Count : Natural := 0;
      Span : Natural := 0;
   end record;
   type Entry_Array is array (Positive range 1 .. Max_Entries) of Index_Entry;
   type Metadata is record
      Entries : Entry_Array := (others => (others => <>));
      Entry_Count : Natural range 0 .. Max_Entries := 0;
      Payload_Offset : Natural := 0;
      Has_Signature_Tag : Boolean := False;
      Has_Executable_Hooks : Boolean := False;
      Is_Source : Boolean := False;
   end record;
   procedure Inspect (Data : Bytes; Info : out Metadata; Status : out Outcome)
     with Global => null,
       Post => (if Status = OK then Info.Payload_Offset <= Data'Length);
   function Find (Info : Metadata; Tag : Word) return Natural
     with Global => null, Post => Find'Result <= Info.Entry_Count;
   -- A successful structural parse is NOT package authentication, signature
   -- verification, dependency validation or permission to install.
   -- This parser supports RPM lead 3/4 with v1 signature/main headers; newer
   -- encodings are rejected. No payload decompression or script execution occurs.
end Pkg_RPM;

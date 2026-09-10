-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Dirents with SPARK_Mode, Pure is
   Max_Names : constant := 512;
   type Name is record Data : String(1..255):=(others=>Character'Val(0)); Length : Natural range 0..255:=0;end record;
   type Name_Array is array(Positive range 1..Max_Names) of Name;
   type Listing is record Names : Name_Array; Count : Natural range 0..Max_Names:=0;end record;
   function Image(N : Name) return String with Global=>null;
   procedure Append_Linux64_LE (Data : Bytes; L : in out Listing; Status : out Outcome) with Global=>null,
     Post => (if Status/=OK then L=L'Old);
   procedure Sort(L : in out Listing) with Global=>null;
   -- Linux getdents64 layout, little-endian. No d_type trust and no path following.
   -- Atomic per buffer: malformed/truncated/duplicate/overflow leaves L unchanged.
end MC_Dirents;

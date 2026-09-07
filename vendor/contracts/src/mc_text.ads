-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Text with SPARK_Mode, Pure is
   Max_Length : constant := 4_096;
   type Value is private;
   Empty : constant Value;
   function Length (V : Value) return Natural with Global => null;
   function Image (V : Value) return String with Global => null;
   procedure Set (V : out Value; S : String; Status : out Outcome)
     with Global => null, Post => (if Status = OK then Image (V) = S);
   function Equal (A, B : Value) return Boolean with Global => null;
   function Identifier (S : String) return Boolean with Global => null;
   function HTTPS_URL (S : String) return Boolean with Global => null;
private
   type Value is record
      Data : String (1 .. Max_Length) := (others => Character'Val (0));
      Used : Natural range 0 .. Max_Length := 0;
   end record;
   Empty : constant Value := (others => <>);
end MC_Text;

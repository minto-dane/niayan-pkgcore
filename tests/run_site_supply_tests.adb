-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Clock; with MC_Codec; with MC_SHA256;
with Pkg_Site_Supply; with Pkg_Supply_Policy;
with Test_Support; use Test_Support;
procedure Run_Site_Supply_Tests with SPARK_Mode => Off is
   package P renames Pkg_Site_Supply;
   use type Byte; use type Wide;
   type Offsets is array (Positive range <>) of Positive;
   Wire : Bytes (1 .. P.Maximum_Size + 1) := (others => 0);
   Anchor : Bytes (1 .. P.Floor_Size + 1) := (others => 0);
   Value : P.Policy; Floor : P.Floor; Result : Outcome;
   Root : constant Identity := (others => 31); Tx : constant Identity := (others => 32);
   Plan : constant Digest := (others => 33); Policy : constant Digest := (others => 34);
   Map : constant Digest := (others => 35);
   Context : P.Session; Observed : Pkg_Supply_Policy.Snapshot; Now, Deadline : Counter;
   procedure Need (Label_Text : String) is
   begin Expect (Result = OK, Label_Text & Outcome'Image (Result)); end Need;
   procedure Refuse (Data : Bytes) is
   begin
      P.Decode (Data, Value, Result);
      Expect (Result /= OK and then Value.Root_ID = Zero_Identity and then Value.Count = 0,
              "invalid policy clears observation");
   end Refuse;
   procedure Refuse_Floor (Data : Bytes) is
   begin
      P.Decode_Floor (Data, Floor, Result);
      Expect (Result /= OK and then Floor.Policy_Hash = Zero_Digest and then Floor.Root_ID = Zero_Identity,
              "invalid floor clears observation");
   end Refuse_Floor;
   procedure Observe (ID : Identity := Tx) is
   begin P.Observe (Context, Root, ID, Plan, Policy, Observed, Result); end Observe;
   procedure Hidden is
   begin
      Expect (Result /= OK and then Observed.Map = Zero_Digest and then Observed.Count = 0
         and then Observed.Observed_At = 0, "failed provider clears all observation");
   end Hidden;
begin
   MC_Runtime.Initialize (Result); Need ("runtime");
   Wire (1 .. 8) := (78, 73, 65, 84, 82, 83, 84, 49); Wire (9 .. 24) := Root;
   MC_Codec.Put64 (Wire, 25, 7); MC_Codec.Put64 (Wire, 33, 1); MC_Codec.Put64 (Wire, 41, 2 ** 53 - 1);
   MC_Codec.Put64 (Wire, 49, 1);
   Wire (57 .. 88) := (others => 1); Wire (89 .. 120) := (others => 2);
   MC_Codec.Put64 (Wire, 121, 7); MC_Codec.Put64 (Wire, 129, 600);
   P.Decode (Wire (1 .. 136), Value, Result); Need ("canonical independent policy");
   Expect (Value.Root_ID = Root and then Value.Count = 1 and then Value.Trusted (1).Minimum_Epoch = 7,
           "policy fields");
   for Length in 0 .. 135 loop Refuse (Wire (1 .. Length)); end loop;
   Refuse (Wire (1 .. 137)); Refuse (Wire); Refuse (Wire (2 .. 137));
   for Offset of Offsets'(25, 33, 41, 121, 129) loop
      declare Changed : Bytes := Wire (1 .. 136); begin
         MC_Codec.Put64 (Changed, Offset, 0); Refuse (Changed);
         MC_Codec.Put64 (Changed, Offset, 2 ** 53); Refuse (Changed);
      end;
   end loop;
   for Kind in 1 .. 6 loop
      declare Changed : Bytes := Wire (1 .. 136); begin
         case Kind is
            when 1 => Changed (1) := 0;
            when 2 => Changed (9 .. 24) := (others => 0);
            when 3 => Changed (57 .. 88) := (others => 0);
            when 4 => Changed (89 .. 120) := (others => 0);
            when 5 => MC_Codec.Put64 (Changed, 49, 257);
            when 6 => MC_Codec.Put64 (Changed, 41, 1);
         end case;
         Refuse (Changed);
      end;
   end loop;
   MC_Codec.Put64 (Wire, 49, 256);
   for I in 1 .. 256 loop
      declare Offset : constant Natural := P.Header_Size + (I - 1) * P.Entry_Size; begin
         Wire (Offset + 1 .. Offset + 32) := (others => 0);
         MC_Codec.Put32 (Wire, Offset + 29, Word (I));
         Wire (Offset + 33 .. Offset + 64) := (others => 2);
         MC_Codec.Put64 (Wire, Offset + 65, 7); MC_Codec.Put64 (Wire, Offset + 73, 600);
      end;
   end loop;
   P.Decode (Wire (1 .. P.Maximum_Size), Value, Result); Need ("maximum authority count");
   Wire (137 .. 168) := Wire (57 .. 88); Refuse (Wire (1 .. P.Maximum_Size));
   Wire (57 .. 88) := (others => 255); Refuse (Wire (1 .. P.Maximum_Size));
   MC_Codec.Put64 (Wire, 49, 0);
   P.Decode (Wire (1 .. P.Header_Size), Value, Result); Need ("empty policy is representable, not an execution grant");
   Anchor (1 .. 8) := (78, 73, 65, 70, 76, 79, 82, 49); Anchor (9 .. 24) := Root;
   MC_Codec.Put64 (Anchor, 25, 7); MC_Codec.Put64 (Anchor, 33, 1);
   Anchor (41 .. 72) := MC_SHA256.Hash (Wire (1 .. P.Header_Size));
   P.Decode_Floor (Anchor (1 .. P.Floor_Size), Floor, Result); Need ("independent floor");
   for Length in 0 .. P.Floor_Size - 1 loop Refuse_Floor (Anchor (1 .. Length)); end loop;
   Refuse_Floor (Anchor); Refuse_Floor (Anchor (2 .. P.Floor_Size + 1));
   for Kind in 1 .. 5 loop
      declare Changed : Bytes := Anchor (1 .. P.Floor_Size); begin
         case Kind is
            when 1 => Changed (1) := 0;
            when 2 => Changed (9 .. 24) := (others => 0);
            when 3 => Changed (41 .. 72) := (others => 0);
            when 4 => MC_Codec.Put64 (Changed, 25, 0);
            when 5 => MC_Codec.Put64 (Changed, 33, 2 ** 53);
         end case;
         Refuse_Floor (Changed);
      end;
   end loop;
   MC_Clock.Boottime_Milliseconds (Deadline, Result); Need ("deadline"); Deadline := Deadline + 30_000;
   if Ada.Command_Line.Argument_Count >= 2 then
      P.Open (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Root, Tx, Plan, Policy, Map, Deadline, Context, Result);
      Need ("actual protected site inputs");
      MC_Clock.Realtime_Seconds (Now, Result); Need ("independent clock"); Observe; Need ("actual supply observation");
      Expect (Observed.Map = Map and then Observed.Count = 1 and then Observed.Observed_At >= Now
         and then Observed.Trusted (1).Minimum_Epoch = 7, "independent keys and current UTC");
      if Ada.Command_Line.Argument_Count = 3 then
         Ada.Text_IO.Put_Line ("READY"); Ada.Text_IO.Flush;
         declare Line : constant String := Ada.Text_IO.Get_Line; begin
            Expect (Line = "changed", "owned VM coordinator changed the policy");
         end;
         Observe; Hidden; Observe; Hidden;
      else
         Observe (Zero_Identity); Hidden; Observe; Hidden;
         P.Open (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Root, Tx, Plan, Policy, Map,
            Deadline, Context, Result); Need ("explicit new session after refusal");
         Observe; Need ("fresh session");
      end if;
   else
      P.Open (Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (1), Root, Tx, Plan, Policy, Map,
         Deadline, Context, Result); Expect (Result /= OK, "caller-owned directory is not site trust");
      Observe; Hidden;
   end if;
   P.Close (Context); Observe; Hidden;
   P.Open ("/", "/", Root, Tx, Plan, Policy, Map, Counter'Last, Context, Result);
   Expect (Result /= OK, "unbounded deadline refused"); Observe; Hidden;
   Report;
end Run_Site_Supply_Tests;

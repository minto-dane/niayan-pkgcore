-- SPDX-License-Identifier: MIT
with MC_Codec;
package body Resolver_Wire with SPARK_Mode is
   use type Byte; use type Word; use type Wide;
   Magic : constant Bytes := (77,67,82,83,79,76,48,49); -- MCRSOL01
   Plan_Magic : constant Bytes := (77,67,82,80,76,78,48,49); -- MCRPLN01
   function Size (U : Universe) return Natural is
      (Header_Size + U.Item_Count * 124 + U.Node_Count * 16
         + U.Rule_Count * 40 + U.Claim_Count * 104);
   procedure Encode (U : Universe; B : out Bytes; Used : out Natural; Status : out Outcome) is
      P : Positive := 1;
      procedure N (X : Natural) is begin MC_Codec.Put32 (B, P, Word (X)); P := P + 4; end;
      procedure C (X : Counter) is begin MC_Codec.Put64 (B, P, Wide (X)); P := P + 8; end;
      procedure D (X : Digest) is begin B (P .. P + 31) := X; P := P + 32; end;
   begin
      B := (others => 0); Used := 0; Status := Invalid_Input;
      if B'First /= 1 or else not Well_Formed (U) then return; end if;
      if B'Length < Size (U) then Status := Exhausted; return; end if;
      B (1 .. 8) := Magic; P := 9;
      D (U.Subject.Root); D (U.Subject.Boot); D (U.Subject.Snapshot); D (U.Subject.Policy);
      D (U.Subject.Adapter_Set); D (U.Subject.Native_Inventory); D (U.Subject.Configuration); D (U.Subject.Effect_Contracts);
      C (U.Subject.Generation); N (U.Item_Count); N (U.Node_Count); N (U.Rule_Count); N (U.Claim_Count);
      N (U.Maximum_Changes); C (U.Maximum_Transfer);
      for I in 1 .. U.Item_Count loop
         declare X : Item renames U.Items (I); begin
            D (X.Object_Hash); D (X.Metadata_Hash); D (X.Adapter_Hash);
            B (P) := Boolean'Pos (X.Initially_Present); B (P + 1) := Boolean'Pos (X.Permitted);
            B (P + 2) := Boolean'Pos (X.Reinstall_Requested); B (P + 3) := Pin_Mode'Pos (X.Pin); P := P + 4;
            C (X.Transfer_Bytes); N (X.Add_Pre); N (X.Add_Post); N (X.Remove_Pre); N (X.Remove_Post);
         end;
      end loop;
      for I in 1 .. U.Node_Count loop
         N (Operator'Pos (U.Nodes (I).Op)); N (U.Nodes (I).Subject); N (U.Nodes (I).Left); N (U.Nodes (I).Right);
      end loop;
      for I in 1 .. U.Rule_Count loop
         N (U.Rules (I).Predicate); N (Rule_Scope'Pos (U.Rules (I).Scope)); D (U.Rules (I).Origin);
      end loop;
      for I in 1 .. U.Claim_Count loop
         D (U.Claims (I).Resource); D (U.Claims (I).Content); D (U.Claims (I).Attributes);
         N (U.Claims (I).Owner); N (Boolean'Pos (U.Claims (I).Shared_Identical));
      end loop;
      Used := P - 1; Status := OK;
   end Encode;
   procedure Decode (B : Bytes; U : out Universe; Status : out Outcome) is
      P : Positive := 9; Bad : Boolean := False;
      function N (Limit : Natural) return Natural is
         X : Word;
      begin
         if P > B'Last or else B'Last - P < 3 then Bad := True; return 0; end if;
         X := MC_Codec.U32 (B, P); P := P + 4;
         if X > Word (Limit) then Bad := True; return 0; end if; return Natural (X);
      end;
      function C return Counter is
         X : Wide;
      begin
         if P > B'Last or else B'Last - P < 7 then Bad := True; return 0; end if;
         X := MC_Codec.U64 (B, P); P := P + 8;
         if X > Wide (Counter'Last) then Bad := True; return 0; end if; return Counter (X);
      end;
      function D return Digest is
         X : Digest := Zero_Digest;
      begin
         if P > B'Last or else B'Last - P < 31 then Bad := True; return X; end if;
         X := B (P .. P + 31); P := P + 32; return X;
      end;
      function Byte_Value (Limit : Byte) return Natural is
         X : Byte;
      begin
         if P > B'Last then Bad := True; return 0; end if;
         X := B (P); P := P + 1;
         if X > Limit then Bad := True; return 0; end if; return Natural (X);
      end;
   begin
      U := (others => <>); Status := Invalid_Input;
      if B'First /= 1 or else B'Length < Header_Size or else B'Length > Maximum_Universe_Bytes
         or else B (1 .. 8) /= Magic then return; end if;
      U.Subject.Root := D; U.Subject.Boot := D; U.Subject.Snapshot := D; U.Subject.Policy := D;
      U.Subject.Adapter_Set := D; U.Subject.Native_Inventory := D;
      U.Subject.Configuration := D; U.Subject.Effect_Contracts := D;
      U.Subject.Generation := C; U.Item_Count := N (Max_Items); U.Node_Count := N (Max_Nodes);
      U.Rule_Count := N (Max_Rules); U.Claim_Count := N (Max_Claims);
      U.Maximum_Changes := N (Max_Steps); U.Maximum_Transfer := C;
      if Bad or else B'Length /= Size (U) then return; end if;
      for I in 1 .. U.Item_Count loop
         U.Items (I).Object_Hash := D; U.Items (I).Metadata_Hash := D; U.Items (I).Adapter_Hash := D;
         U.Items (I).Initially_Present := Boolean'Val (Byte_Value (1));
         U.Items (I).Permitted := Boolean'Val (Byte_Value (1));
         U.Items (I).Reinstall_Requested := Boolean'Val (Byte_Value (1));
         U.Items (I).Pin := Pin_Mode'Val (Byte_Value (3)); U.Items (I).Transfer_Bytes := C;
         U.Items (I).Add_Pre := N (Max_Nodes); U.Items (I).Add_Post := N (Max_Nodes);
         U.Items (I).Remove_Pre := N (Max_Nodes); U.Items (I).Remove_Post := N (Max_Nodes);
      end loop;
      for I in 1 .. U.Node_Count loop
         U.Nodes (I).Op := Operator'Val (N (5)); U.Nodes (I).Subject := N (Max_Items);
         U.Nodes (I).Left := N (Max_Nodes); U.Nodes (I).Right := N (Max_Nodes);
      end loop;
      for I in 1 .. U.Rule_Count loop
         U.Rules (I).Predicate := N (Max_Nodes); U.Rules (I).Scope := Rule_Scope'Val (N (1)); U.Rules (I).Origin := D;
      end loop;
      for I in 1 .. U.Claim_Count loop
         U.Claims (I).Resource := D; U.Claims (I).Content := D; U.Claims (I).Attributes := D;
         U.Claims (I).Owner := N (Max_Items); U.Claims (I).Shared_Identical := Boolean'Val (N (1));
      end loop;
      if not Bad and then P = B'Last + 1 and then Well_Formed (U) then Status := OK; end if;
   end Decode;
   procedure Encode_Proposal (P : Proposal; Item_Count : Item_ID;
      B : out Bytes; Used : out Natural; Status : out Outcome) is
      Pos : Positive; Required : constant Natural := 48 + Item_Count + P.Count * 8;
   begin
      B := (others => 0); Used := 0; Status := Invalid_Input;
      if B'First /= 1 or else Is_Zero (P.Universe_Hash) then return; end if;
      if B'Length < Required then Status := Exhausted; return; end if;
      for I in Item_Count + 1 .. Max_Items loop if P.Selected (I) then return; end if; end loop;
      B (1 .. 8) := Plan_Magic; B (9 .. 40) := P.Universe_Hash;
      MC_Codec.Put32 (B, 41, Word (Item_Count)); Pos := 45;
      for I in 1 .. Item_Count loop B (Pos) := Boolean'Pos (P.Selected (I)); Pos := Pos + 1; end loop;
      MC_Codec.Put32 (B, Pos, Word (P.Count)); Pos := Pos + 4;
      for I in 1 .. P.Count loop
         if P.Steps (I).Subject = 0 or else P.Steps (I).Subject > Item_Count then return; end if;
         MC_Codec.Put32 (B, Pos, Word (Action_Kind'Pos (P.Steps (I).Kind)));
         MC_Codec.Put32 (B, Pos + 4, Word (P.Steps (I).Subject)); Pos := Pos + 8;
      end loop;
      Used := Pos - 1; Status := OK;
   end Encode_Proposal;
   procedure Decode_Proposal (B : Bytes; Item_Count : Item_ID;
      P : out Proposal; Status : out Outcome) is
      Pos : Positive := 45; X, Y : Word;
   begin
      P := (others => <>); Status := Invalid_Input;
      if B'First /= 1 or else B'Length < 48 + Item_Count or else B'Length > Maximum_Proposal_Bytes
        or else B (1 .. 8) /= Plan_Magic or else MC_Codec.U32 (B, 41) /= Word (Item_Count) then return; end if;
      P.Universe_Hash := B (9 .. 40); if Is_Zero (P.Universe_Hash) then return; end if;
      for I in 1 .. Item_Count loop
         if B (Pos) > 1 then return; end if; P.Selected (I) := B (Pos) = 1; Pos := Pos + 1;
      end loop;
      X := MC_Codec.U32 (B, Pos); Pos := Pos + 4; if X > Max_Steps then return; end if;
      P.Count := Natural (X); if B'Length /= 48 + Item_Count + P.Count * 8 then return; end if;
      for I in 1 .. P.Count loop
         X := MC_Codec.U32 (B, Pos); Y := MC_Codec.U32 (B, Pos + 4); Pos := Pos + 8;
         if X > 2 or else Y = 0 or else Y > Word (Item_Count) then return; end if;
         P.Steps (I) := (Action_Kind'Val (X), Item_ID (Y));
      end loop;
      Status := OK;
   end Decode_Proposal;
end Resolver_Wire;

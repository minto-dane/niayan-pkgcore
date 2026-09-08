-- SPDX-License-Identifier: MIT
package body Resolver_Model with SPARK_Mode is
   use type Byte;
   function Less (A, B : Digest) return Boolean is
   begin
      for I in A'Range loop
         if A (I) /= B (I) then return A (I) < B (I); end if;
      end loop;
      return False;
   end Less;
   function Binding_Valid (B : Binding) return Boolean is
     (not Is_Zero (B.Root) and then not Is_Zero (B.Boot)
      and then not Is_Zero (B.Snapshot) and then not Is_Zero (B.Policy)
      and then not Is_Zero (B.Adapter_Set) and then not Is_Zero (B.Native_Inventory)
      and then not Is_Zero (B.Configuration) and then not Is_Zero (B.Effect_Contracts)
      and then B.Generation > 0);
   function Well_Formed (U : Universe) return Boolean is
   begin
      if not Binding_Valid (U.Subject) or else U.Item_Count = 0
        or else not References_Valid(U) then return False; end if;
      for I in 1 .. U.Item_Count loop
         declare P : Item renames U.Items (I); begin
            if Is_Zero (P.Object_Hash) or else Is_Zero (P.Metadata_Hash)
              or else Is_Zero (P.Adapter_Hash)
              or else P.Add_Pre > U.Node_Count or else P.Add_Post > U.Node_Count
              or else P.Remove_Pre > U.Node_Count or else P.Remove_Post > U.Node_Count
              or else (P.Reinstall_Requested and then not P.Initially_Present)
            then return False; end if;
            if I > 1 and then not Less (U.Items (I - 1).Object_Hash, P.Object_Hash)
            then return False; end if;
         end;
      end loop;
      for I in 1 .. U.Rule_Count loop
         if Is_Zero (U.Rules (I).Origin) then return False; end if;
      end loop;
      for I in 1 .. U.Claim_Count loop
         declare C : Claim renames U.Claims (I); begin
            if Is_Zero (C.Resource)
              or else Is_Zero (C.Content) or else Is_Zero (C.Attributes) then return False; end if;
            if I > 1 then
               if Less (C.Resource, U.Claims (I - 1).Resource) then return False; end if;
               if C.Resource = U.Claims (I - 1).Resource and then C.Owner <= U.Claims (I - 1).Owner
               then return False; end if;
            end if;
         end;
      end loop;
      -- Unused array storage is not serialized; wire decoding initializes it.
      return True;
   end Well_Formed;
   function Initial (U : Universe) return Selection is
      S : Selection := (others => False);
   begin
      for I in 1 .. U.Item_Count loop S (I) := U.Items (I).Initially_Present; end loop;
      return S;
   end Initial;
   function Canonical_Selection (U : Universe; S : Selection) return Boolean is
   begin
      for I in U.Item_Count + 1 .. Max_Items loop if S (I) then return False; end if; end loop;
      return True;
   end Canonical_Selection;
   procedure Evaluate (U : Universe; S : Selection; Values : out Truth_Array) is
   begin
      Values := (others => False);
      for I in 1 .. U.Node_Count loop
         declare N : Expression_Node renames U.Nodes (I); begin
            case N.Op is
               when Constant_False => Values (I) := False;
               when Constant_True => Values (I) := True;
               when Present => Values (I) := S (N.Subject);
               when Not_Op => Values (I) := not Values (N.Left);
               when And_Op => Values (I) := Values (N.Left) and Values (N.Right);
               when Or_Op => Values (I) := Values (N.Left) or Values (N.Right);
            end case;
         end;
      end loop;
   end Evaluate;
   function Predicate_Holds (ID : Node_ID; Values : Truth_Array) return Boolean is
     (ID = 0 or else Values (ID));
   function Claims_Compatible (A, B : Claim) return Boolean is
     (A.Resource /= B.Resource or else A.Owner = B.Owner
      or else (A.Shared_Identical and then B.Shared_Identical
        and then A.Content = B.Content and then A.Attributes = B.Attributes));
end Resolver_Model;

open Util
open Pos
open Err
open Tast
open Tast_util

let sprintf = Printf.sprintf

let contains fn =
  match fn.data with
    | "memzero" -> true
    | _ -> false

let name_of code =
  let ps_lbl = function
    | Public -> "public"
    | Secret -> "secret" in
    make_ast fake_pos
      begin
        match code with
          | Memzero (sz,lbl,everhi) ->
            sprintf "__memzero[%d]/%s%s" sz (ps_lbl lbl) (if everhi then "oblivious" else "")
      end

let wmem sz lbl =
  let p = fake_pos in
    [ p@>Param (p@>"mem",
                p@>Arr (p@>Ref (p@>UInt (sz,lbl),p@>W),p@>LDynamic (p@>"len"),default_var_attr)) ;
      p@>Param (p@>"len",
                p@>UInt (64,p@>Public)) ]

let interface_of (tc_expr : Ast.expr -> Tast.expr) p stmlbl fn args =
  match fn.data with
    | "memzero" ->
      let arg = match args with
        | [arg] -> arg
        | _ -> raise @@ err p in
      let arg' = tc_expr arg in
      let subty,lexpr = match (type_of arg').data with
        | Arr ({data=Ref (subty,{data=W|RW})},lexpr,_) -> subty,lexpr
        | _ -> raise @@ err p in
      let sz,lbl = match subty.data with
        | UInt (s,l) -> s,l
        | _ -> raise @@ err p in
      let rt' = None in
      let params' = wmem sz lbl in
      let arglen = p@>Ast.ArrayLen arg in
      let args' = [ arg; arglen ] in
      let everhi = match stmlbl.data with
        | Public -> false
        | Secret -> true in
      let fdec' = fake_pos @> StdLibFn (Memzero (sz,lbl.data,everhi),{ export=false; inline=Default; everhi },rt',params') in
        fdec',args'

let llvm_for llctx llmod code =
  Llvm.(
    let _i1ty = i1_type llctx in
    let i8ty = i8_type llctx in
    let _i16ty = i16_type llctx in
    let _i32ty = i32_type llctx in
    let i64ty = i64_type llctx in
    let _i128ty = integer_type llctx 128 in
    let voidty = void_type llctx in
    let _memty = pointer_type i8ty in
    let _noinline = create_enum_attr llctx "noinline" 0L in
    let alwaysinline = create_enum_attr llctx "alwaysinline" 0L in
    let _get_intrinsic = Intrinsics.make_stuff llctx llmod in

    let built : Llvm.llvalue -> unit = ignore in

    let def_internal name ft =
      let fn = define_function name ft llmod in
        add_function_attr fn alwaysinline Function;
        set_linkage Internal fn;
        let bb = entry_block fn in
        let b = builder llctx in
          position_at_end bb b;
          fn,b in

      match code with
        | Memzero (sz,_,everhi) ->
          let name = name_of code in
          let pty = pointer_type (integer_type llctx sz) in
          let ft = function_type voidty [| pty; i64ty |] in
          let fn,b = def_internal name.data ft in
          let dst = param fn 0 in
          let len = param fn 1 in
          let zero = const_null i8ty in
          let memset = _get_intrinsic (Memset sz) in
            build_call memset [| dst; zero; len |] "" b |> built;
            build_ret_void b |> built;
            fn
  )

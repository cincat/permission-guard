package pg.guard;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import soot.ArrayType;
import soot.Body;
import soot.BodyTransformer;
import soot.IntType;
import soot.Local;
import soot.Modifier;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.VoidType;
import soot.javaToJimple.LocalGenerator;
import soot.jimple.ArrayRef;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.NeExpr;
import soot.jimple.NewArrayExpr;
import soot.jimple.NopStmt;
import soot.jimple.StringConstant;
import soot.util.Chain;

public class PermissionTransformer extends BodyTransformer {

	@Override
	protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
		// TODO Auto-generated method stub
		SootClass c = b.getMethod().getDeclaringClass();
		
		
		Chain<Unit> units = b.getUnits();
		Iterator<Unit> iter = units.snapshotIterator();
		
		while (iter.hasNext()) {
			Unit unit = iter.next();
			instrumentCheckAndCallback(unit, b);
		}
	}
	
	private boolean isActivity(SootClass c) {
		SootClass sc = c;
		while (sc.hasSuperclass()) {
			if (sc.getName().equals("android.app.Activity")) {
				return true;
			}
			sc = sc.getSuperclass();
		}
		return false;
	}

	private void instrumentCheckAndCallback(Unit unit, Body body) {
		if (!(unit instanceof InvokeStmt))
			return;
//		static method has no this local;
		if (body.getMethod().isStatic()) {
			return ;
		}
		InvokeStmt stmt = (InvokeStmt) unit;
		SootMethod method = stmt.getInvokeExpr().getMethod();
		if (Guard.injectMethodMeta.contains(method.getSignature()) == false) {
			return;
		}
			
		if (isActivity(body.getMethod().getDeclaringClass()) == false) {
			return;
		}
		
		if (method.getSignature().contains("<init>")) {
			return ;
		}
		System.out.println(method.getSignature());
//		SootClass c = body.getMethod().getDeclaringClass();
//		while (c.hasSuperclass()) {
//			System.out.println(c.getName());
//			c = c.getSuperclass();
//		}
		int requestCode = Guard.injectMethodMeta.indexOf(method.getSignature());
		int length = Guard.injectPermissionMeta.get(requestCode).size();
		Chain<Unit> units = body.getUnits();

		SootMethod checker = Scene.v().getMethod("<android.support.v4.content.ContextCompat:"
				+ " int checkSelfPermission(android.content.Context,java.lang.String)>");
		//
		Local permissionToBeChecked = null;
		// for loop to copy permission list to jimple
		{
			List<Unit> patchUnits = new ArrayList<>();
			permissionToBeChecked = generateNewLocal(body, ArrayType.v(RefType.v("java.lang.String"), 1));
			NewArrayExpr newArrayExpr = Jimple.v().newNewArrayExpr(RefType.v("java.lang.String"),
					IntConstant.v(length));
			patchUnits.add(Jimple.v().newAssignStmt(permissionToBeChecked, newArrayExpr));

			for (int i = 0; i < length; i++) {
				ArrayRef item = Jimple.v().newArrayRef(permissionToBeChecked, IntConstant.v(i));
				patchUnits.add(Jimple.v().newAssignStmt(item,
						StringConstant.v(Guard.injectPermissionMeta.get(requestCode).get(i))));
			}
			units.insertBefore(patchUnits, unit);
		}
		
		Local hasAllPermission = generateNewLocal(body, IntType.v());
		// Jimple.v().newAssignStmt(hasAllPermission, IntConstant.v(1));
		units.insertBefore(Jimple.v().newAssignStmt(hasAllPermission, IntConstant.v(1)), unit);
		// for loop to check all permission needed, at mean time set hasAllPermission 1
		// if condition meets;
		{
			Local i = generateNewLocal(body, IntType.v());
			List<Unit> patchUnits = new ArrayList<>();
			patchUnits.add(Jimple.v().newAssignStmt(i, IntConstant.v(0)));

			NopStmt nop = Jimple.v().newNopStmt();
			IfStmt ifStmt = Jimple.v().newIfStmt(Jimple.v().newGeExpr(i, IntConstant.v(length)), nop);
			patchUnits.add(ifStmt);
			ArrayRef item = Jimple.v().newArrayRef(permissionToBeChecked, i);
			Local hasPermission = generateNewLocal(body, IntType.v());
			Local tmp = generateNewLocal(body, RefType.v("java.lang.String"));
			patchUnits.add(Jimple.v().newAssignStmt(tmp, item));
			patchUnits.add(Jimple.v().newAssignStmt(hasPermission, Jimple.v()
					.newStaticInvokeExpr(checker.makeRef(), body.getThisLocal(), tmp)));
			NopStmt nop2 = Jimple.v().newNopStmt();
			IfStmt ifStmt2 = Jimple.v().newIfStmt(Jimple.v().newEqExpr(hasPermission, IntConstant.v(0)),
					nop2);
			patchUnits.add(ifStmt2);
			patchUnits.add(Jimple.v().newAssignStmt(hasAllPermission, IntConstant.v(0)));
			GotoStmt gotoStmt = Jimple.v().newGotoStmt(nop);
			patchUnits.add(gotoStmt);
			patchUnits.add(nop2);
			patchUnits.add(Jimple.v().newAssignStmt(i, Jimple.v().newAddExpr(i, IntConstant.v(1))));
			GotoStmt gotoStmt2 = Jimple.v().newGotoStmt(ifStmt);
			patchUnits.add(gotoStmt2);
			patchUnits.add(nop);
			units.insertBefore(patchUnits, unit);
		}

		// request permission
		{
			SootMethod requester = Scene.v().getMethod("<android.support.v4.app.ActivityCompat:"
					+ " void requestPermissions(android.app.Activity,java.lang.String[],int)>");
			List<Unit> patchUnits = new ArrayList<>();
			NopStmt nop = Jimple.v().newNopStmt();
			IfStmt ifStmt = Jimple.v().newIfStmt(Jimple.v().newEqExpr(hasAllPermission, IntConstant.v(1)),
					nop);
			patchUnits.add(ifStmt);
			patchUnits.add(Jimple.v()
					.newInvokeStmt(Jimple.v().newStaticInvokeExpr(requester.makeRef(),
							body.getThisLocal(), permissionToBeChecked,
							IntConstant.v(requestCode))));
			NopStmt nop2 = Jimple.v().newNopStmt();
			units.insertAfter(nop2, unit);
			GotoStmt gotoStmt = Jimple.v().newGotoStmt(nop2);
			patchUnits.add(gotoStmt);
			patchUnits.add(nop);
			units.insertBefore(patchUnits, unit);
		}
		

		if (method.getDeclaringClass()
				.getMethodUnsafe("void onRequestPermissionsResult(int, java.lang.String[], int[])") == null) {
			instrumentCallback(method, requestCode);
			return;
		}

		if (hasCallbackForMethod(method) == true) {
			return;
		}

		instrumentInCallback(method);
		
//		body.validate();
	}

	private void instrumentCallback(SootMethod method, int requestCode) {
//		SootClass c = method.getDeclaringClass();
//		SootMethod m = new SootMethod("onRequestPermissionsResult", Arrays.asList(new Type[] { IntType.v(),
//				ArrayType.v(RefType.v("java.lang.String"), 1), ArrayType.v(IntType.v(), 1) }),
//				VoidType.v(), Modifier.PUBLIC);
////		FIX ME
//		if (c.declaresMethodByName("onRequestPermissionsResult")) {
//			return ;
//		}
//		c.addMethod(m);
//		JimpleBody b = Jimple.v().newBody(m);
//		m.setActiveBody(b);
//
//		// create locals
//		Local r0 = Jimple.v().newLocal("r0", RefType.v(c.getName()));
//		Local r1 = Jimple.v().newLocal("r1", ArrayType.v(RefType.v("java.lang.String"), 1));
//		Local r2 = Jimple.v().newLocal("r2", ArrayType.v(IntType.v(), 1));
//		Local r3 = Jimple.v().newLocal("r3", RefType.v("android.widget.Toast"));
//		Local i0 = Jimple.v().newLocal("i0", IntType.v());
//
//		//
//		b.getLocals().add(r0);
//		b.getLocals().add(r1);
//		b.getLocals().add(r2);
//		b.getLocals().add(r3);
//		b.getLocals().add(i0);
//
//		// difference between identityStmt and assignStmt?
//		Chain<Unit> units = b.getUnits();
//		units.add(Jimple.v().newIdentityStmt(r0, Jimple.v().newThisRef(RefType.v(c.getName()))));
//		units.add(Jimple.v().newIdentityStmt(i0, Jimple.v().newParameterRef(IntType.v(), 0)));
//		units.add(Jimple.v().newIdentityStmt(r1,
//				Jimple.v().newParameterRef(ArrayType.v(RefType.v("java.lang.String"), 1), 1)));
//		units.add(Jimple.v().newIdentityStmt(r2, Jimple.v().newParameterRef(ArrayType.v(IntType.v(), 1), 2)));
//
//		NopStmt nop1 = Jimple.v().newNopStmt();
//		NeExpr neExpr1 = Jimple.v().newNeExpr(i0, IntConstant.v(requestCode));
//		IfStmt ifStmt1 = Jimple.v().newIfStmt(neExpr1, nop1);
//		//
//		// outer if statement
//		{
//			units.add(ifStmt1);
//			NopStmt nop2 = Jimple.v().newNopStmt();
//			
////			condition indicate r2.length > 0
//			units.add(Jimple.v().newAssignStmt(i0, Jimple.v().newLengthExpr(r2)));
//			units.add(Jimple.v().newIfStmt(Jimple.v().newEqExpr(i0, IntConstant.v(0)), nop2));
//			
//			ArrayRef firstItem = Jimple.v().newArrayRef(r2, IntConstant.v(0));
//			units.add(Jimple.v().newAssignStmt(i0, firstItem));
//			NeExpr neExpr2 = Jimple.v().newNeExpr(i0, IntConstant.v(0));
//			
//			IfStmt ifStmt2 = Jimple.v().newIfStmt(neExpr2, nop2);
//			// if
//			{
//				units.add(ifStmt2);
////				SootMethod callPhone = Scene.v().getMethod(
////						"<com.example.calltest.callPhoneActivity: void callPhone()>");
//				InvokeStmt invokeMethod = Jimple.v().newInvokeStmt(
//						Jimple.v().newVirtualInvokeExpr(r0, method.makeRef()));
//				units.add(invokeMethod);
//				// note: nop1 not nop2
//				GotoStmt skipElse = Jimple.v().newGotoStmt(nop1);
//				units.add(skipElse);
//				units.add(nop2);
//			}
//
//			// else
//			{
//				Scene.v().loadClassAndSupport("android.widget.Toast");
//				SootClass toastClass = Scene.v().getSootClass("android.widget.Toast");
//				SootMethod toast = toastClass.getMethod(
//						"android.widget.Toast makeText(android.content.Context,java.lang.CharSequence,int)");
//				Local tmp = Jimple.v().newLocal("tmp", RefType.v(toastClass));
//				b.getLocals().add(tmp);
//				units.add(Jimple.v().newAssignStmt(tmp, Jimple.v().newStaticInvokeExpr(toast.makeRef(),
//						r0, StringConstant.v("Permission Denied"), IntConstant.v(0))));
//				SootMethod show = Scene.v().getMethod("<android.widget.Toast: void show()>");
//				units.add(Jimple.v()
//						.newInvokeStmt(Jimple.v().newVirtualInvokeExpr(tmp, show.makeRef())));
//				// units.add(Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(toast.makeRef(),
//				// r0,
//				// StringConstant.v("Permission Denied"), IntConstant.v(0))));
//
//				// units.add(Jimple.v()
//				// .newInvokeStmt(Jimple.v().newVirtualInvokeExpr(r0, show.makeRef())));
//			}
//			units.add(nop1);
//		}
//
//		units.add(Jimple.v().newReturnVoidStmt());
//		b.validate();
	}

	private void instrumentInCallback(SootMethod method) {

	}

	private boolean hasCallbackForMethod(SootMethod method) {
		SootMethod callBack = method.getDeclaringClass()
				.getMethod("void onRequestPermissionsResult(int, java.lang.String[], int[])");
		// if (callBack == null) return false;
		Iterator<Unit> iter = callBack.getActiveBody().getUnits().snapshotIterator();
		while (iter.hasNext()) {
			Unit unit = iter.next();
			if (unit instanceof InvokeStmt) {
				InvokeStmt stmt = (InvokeStmt) unit;
				if (stmt.getInvokeExpr().getMethod() == method)
					return true;
			}
		}
		return false;
	}

	private Local generateNewLocal(Body body, Type type) {
		LocalGenerator lg = new LocalGenerator(body);
		return lg.generateLocal(type);
	}

}

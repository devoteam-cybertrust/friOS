/*
 * iOS Frida Hooking Skeleton Script
 * 
 * (c) 2017 INTEGRITY S.A.
 * By: Herman Duarte <hd@integrity.pt>
 */

// lets check if the env is available
if (ObjC.available)
{
	// class or classes that we want to hook methods
	var classes = [''];
	// methods we want to hook, at least from one of the classes above
	var methodsWhiteList = [''];

	for (var className in ObjC.classes)
	{
		if (ObjC.classes.hasOwnProperty(className))
		{
			if (classes.indexOf(className) > -1)
			{
				console.log('[*] Start: Hooking into "' + className + '" methods');
				
				var methods = ObjC.classes[className].$ownMethods;
				for (var i = 0; i < methods.length; i++)
	            {
	            	// if the method is in the whitelist then we can intercepted it
	            	if (methodsWhiteList.indexOf(methods[i]) > -1)
	            	{
		            	try
		            	{
		            		var _className = "" + className;
		            		var _methodName = "" + methods[i];
		            		
			            	var method = ObjC.classes[_className][_methodName];

			            	console.log('Hooking: ' + _methodName);

							Interceptor.attach(method.implementation, {
								onEnter: function (args) {

									this._className = ObjC.Object(args[0]).toString();
		            				this._methodName = ObjC.selectorAsString(args[1]);
									
									console.log("\n[*] Detected call to: " + this._className + " -> " + this._methodName);

									if (this._methodName == '')
									{
								        console.log("    [*] param1: " + (new ObjC.Object(args[2])).toString());
								        console.log("    [*] param2': " + (new ObjC.Object(args[3])).toString());

								        //console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
									}
								},	
								onLeave: function (retval)	{
									if (this._methodName == '' )
									{
										var returnvalue = new ObjC.Object(retval);
	        							console.log("    [*] Return value: " + returnvalue.toString());
        							}
								}
							});
			                console.log('    [*] Hooked: ' + _methodName);
			            }
			            catch(error)
			            {
			            	console.log('Hooking Falied');
			            }
			        }
	            }
				console.log('[*] Completed: Hooking into "' + className + '" methods');
			}
		}
	}

}
else
{
	console.log('Objective-C Runtime is not available!');
}

/*
 * ToDo:
 * - obtain the methods param automatically
 * - create onenter and onleave skeletons to print the params
 */

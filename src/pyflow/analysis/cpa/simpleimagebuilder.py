"""Simple image builder for CPA initial store graph construction.

This module builds the initial "image" of the store graph before CPA analysis.
The image represents the initial state of objects and their relationships based
on entry points and static information.

The image builder:
1. Processes entry points to create initial call arguments
2. Builds object graph for entry point arguments
3. Attaches attributes based on type information
4. Creates initial store graph structure

This provides a starting point for the constraint-based analysis, which then
refines and extends the store graph through constraint solving.
"""

from pyflow.analysis.storegraph import storegraph, canonicalobjects
from pyflow.util.python.calling import CallerArgs


class ImageBuilder(object):
    """Builds initial store graph image from entry points.
    
    This class constructs the initial state of the store graph before CPA analysis.
    It processes entry points (functions that can be called from outside) and builds
    the initial object graph representing their arguments and types.
    
    The image builder uses a worklist algorithm:
    1. Start with entry point arguments
    2. For each object, attach its attributes based on type information
    3. New objects discovered through attributes are added to worklist
    4. Process until fixed point (no new objects)
    
    Attributes:
        compiler: Compiler instance with extractor and other components
        prgm: Program object being analyzed
        allObjects: Set of all objects discovered
        dirtyObjects: Worklist of objects needing attribute attachment
        canonical: CanonicalObjects for type canonicalization
        storeGraph: StoreGraph being built
        entryPoints: List of (entryPoint, CallerArgs) tuples
    """
    def __init__(self, compiler, prgm):
        """Initialize the image builder.
        
        Args:
            compiler: Compiler instance
            prgm: Program object to build image for
        """
        self.compiler = compiler
        self.prgm = prgm

        self.allObjects = set()
        self.dirtyObjects = set()

        self.canonical = canonicalobjects.CanonicalObjects()
        self.storeGraph = storegraph.StoreGraph(self.compiler.extractor, self.canonical)
        self.entryPoints = []

    def objType(self, obj):
        """Get the extended type for a Python object.
        
        Determines whether the object is abstract (external) or concrete (existing),
        and returns the appropriate extended type representation.
        
        Args:
            obj: Python object (program.Object)
            
        Returns:
            ExtendedType for the object
        """
        self.ensureLoaded(obj)
        if obj.isAbstract():
            return self.canonical.externalType(obj)
        else:
            return self.canonical.existingType(obj)

    def objGraphObj(self, obj):
        """Get or create object node in store graph for a Python object.
        
        Creates the store graph representation of a Python object, ensuring
        it's logged for attribute attachment processing.
        
        Args:
            obj: Python object (program.Object)
            
        Returns:
            ObjectNode in the store graph
        """
        xtype = self.objType(obj)

        region = self.storeGraph.regionHint
        obj = region.object(xtype)
        self.logObj(obj)
        return obj

    def logObj(self, obj):
        """Log an object for processing.
        
        Adds object to tracking sets if not already seen. Objects are added
        to dirtyObjects worklist to have their attributes attached.
        
        Args:
            obj: ObjectNode to log
        """
        if obj not in self.allObjects:
            self.allObjects.add(obj)
            self.dirtyObjects.add(obj)

    def ensureLoaded(self, obj):
        """Ensure a Python object and its type are fully loaded.
        
        Sometimes constant folding or other optimizations may leave objects
        partially loaded. This ensures both the object and its type have
        all necessary information (type, typeinfo, etc.).
        
        Args:
            obj: Python object to ensure loaded
        """
        # HACK sometimes constant folding neglects this.
        if not hasattr(obj, "type"):
            self.compiler.extractor.ensureLoaded(obj)

        t = obj.type
        if not hasattr(t, "typeinfo"):
            self.compiler.extractor.ensureLoaded(t)

    def addAttr(self, src, attrName, dst):
        """Add an attribute relationship between objects.
        
        Creates a field in the store graph representing an attribute relationship,
        connecting the source object to the destination object via the attribute name.
        
        Args:
            src: Source Python object
            attrName: Tuple (slottype, name) for the attribute
            dst: Destination Python object
        """
        obj = self.objGraphObj(src)

        fieldName = self.canonical.fieldName(*attrName)
        field = obj.field(fieldName, self.storeGraph.regionHint)

        field.initializeType(self.objType(dst))

    def getExistingSlot(self, pyobj):
        """Get extended type for an existing Python object.
        
        Args:
            pyobj: Python object
            
        Returns:
            ExtendedType for the object
        """
        obj = self.compiler.extractor.getObject(pyobj)
        return self.objGraphObj(obj).xtype

    def getInstanceSlot(self, typeobj):
        """Get extended type for a type instance.
        
        Args:
            typeobj: Type object
            
        Returns:
            ExtendedType for an instance of the type
        """
        obj = self.compiler.extractor.getInstance(typeobj)
        return self.objGraphObj(obj).xtype

    def handleArg(self, arg):
        """Convert an entry point argument to extended type representation.
        
        Entry point arguments may be represented in various ways. This method
        extracts the extended type representation, assuming arguments are
        not polymorphic (single type per argument).
        
        Args:
            arg: Entry point argument (may have get() method)
            
        Returns:
            List containing extended type, or None if argument is None
        """
        # Assumes args are not polymorphic!  (True for now)
        result = arg.get(self)
        if result is None:
            return None
        else:
            return [result]

    def resolveEntryPoint(self, entryPoint):
        """Resolve entry point arguments to CallerArgs format.
        
        Converts an entry point's arguments (self, args, vargs, kargs) into
        the CallerArgs format expected by the CPA system.
        
        Args:
            entryPoint: Entry point object with argument information
            
        Returns:
            CallerArgs object with resolved argument types
        """
        selfarg = self.handleArg(entryPoint.selfarg)
        args = [self.handleArg(arg) for arg in entryPoint.args]
        kwds = []
        varg = self.handleArg(entryPoint.varg)
        karg = self.handleArg(entryPoint.karg)

        return CallerArgs(selfarg, args, kwds, varg, karg, None)

    def attachAttr(self, root):
        """Attach attributes to an object based on its type information.
        
        This method examines the Python type of an object and attaches fields
        to the store graph based on __fieldtypes__ annotations. It traverses
        the MRO (Method Resolution Order) to find all field type declarations.
        
        For each field found:
        1. Creates a field slot in the store graph
        2. Initializes it with the declared field types
        3. Logs discovered objects for further processing
        
        Args:
            root: ObjectNode to attach attributes to
        """
        pt = root.xtype.obj.pythonType()

        for t in type.mro(pt):
            fieldtypes = getattr(t, "__fieldtypes__", None)
            if not isinstance(fieldtypes, dict):
                continue

            for name, types in fieldtypes.items():
                descriptorName = self.compiler.slots.uniqueSlotName(getattr(pt, name))
                nameObj = self.compiler.extractor.getObject(descriptorName)
                fieldName = self.canonical.fieldName("Attribute", nameObj)
                field = root.field(fieldName, self.storeGraph.regionHint)

                if isinstance(types, type):
                    types = (types,)

                for ft in types:
                    inst = self.compiler.extractor.getInstance(ft)
                    field.initializeType(self.objType(inst))

                for obj in field:
                    self.logObj(obj)

    def process(self):
        """Build the initial store graph image.
        
        Main processing method that:
        1. Resolves entry points to create initial call arguments
        2. Processes objects in worklist to attach attributes
        3. Continues until fixed point (no new objects discovered)
        
        The resulting store graph represents the initial state before CPA
        constraint solving, which will refine and extend it.
        """
        interface = self.prgm.interface

        for entryPoint in interface.entryPoint:
            args = self.resolveEntryPoint(entryPoint)
            self.entryPoints.append((entryPoint, args))

        while self.dirtyObjects:
            obj = self.dirtyObjects.pop()
            self.attachAttr(obj)


def build(compiler, prgm):
    """Build initial store graph image for a program.
    
    Main entry point for image building. Creates an ImageBuilder, processes
    the program to build the initial store graph, and attaches it to the
    program object along with resolved entry points.
    
    Args:
        compiler: Compiler instance
        prgm: Program object to build image for
        
    Side effects:
        Modifies prgm.storeGraph and prgm.entryPoints
    """
    ib = ImageBuilder(compiler, prgm)
    ib.process()

    prgm.storeGraph = ib.storeGraph
    prgm.entryPoints = ib.entryPoints

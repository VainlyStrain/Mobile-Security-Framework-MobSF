import treelib

from enum import Enum

from core.variables import separator

class PackageTree(treelib.Tree):
    class PackageNode(treelib.Node):
        def __init__(self, classCount, *args, **kwargs):
            super(PackageNode, self).__init__(*args, **kwargs)
            self.classCount = classCount


class Relationship(Enum):
    PARENT = 0
    CHILD = 1
    SIBLING = 2
    UNRELATED = 3


def parsePackage(name, last=False):
    hierarchy = name.split(".")
    if not last:
        del hierarchy[-1]
    return hierarchy


def packageToPath(name):
    return name.replace(".", separator)


def getPackageName(name):
    return ".".join(parsePackage(name))


def packageDepth(name, last=False):
    return len(parsePackage(name, last=last))


def getMaxDepth(packageNames):
    return max([packageDepth(i) for i in packageNames])


def getSubPackageOfDepth(name, depth):
    hierarchy = parsePackage(name, last=True)
    return hierarchy[depth] if len(hierarchy) - 1 >= depth else null


def testRelationship(name1, name2):
    depth1, depth2 = packageDepth(name1), packageDepth(name2)
    if depth1 > depth2 and name1.startswith(name2):
        return Relationship.PARENT
    elif depth1 < depth2 and name2.startswith(name1):
        return Relationship.CHILD
    elif name1 == name2:
        return Relationship.SIBLING
    else:
        return Relationship.UNRELATED

"""Retarget a glTF skin onto an exported Replay humanoid bind skeleton.

Produces native writer input, preserving all source triangles and at most four
weighted influences. The target skeleton and material must come from the actual
Replay build; names alone do not certify animation compatibility.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import numpy as np
from PIL import Image


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rotation(q):
    x, y, z, w = np.asarray(q, dtype=float) / np.linalg.norm(q)
    return np.array([[1-2*y*y-2*z*z, 2*x*y-2*z*w, 2*x*z+2*y*w],
                     [2*x*y+2*z*w, 1-2*x*x-2*z*z, 2*y*z-2*x*w],
                     [2*x*z-2*y*w, 2*y*z+2*x*w, 1-2*x*x-2*y*y]])


class Glb:
    def __init__(self, path):
        self.path = Path(path)
        data = self.path.read_bytes()
        magic, version, length = struct.unpack_from('<III', data)
        if magic != 0x46546C67 or version != 2 or length != len(data):
            raise ValueError('Invalid glTF 2 GLB')
        chunks, at = {}, 12
        while at < len(data):
            size, kind = struct.unpack_from('<II', data, at)
            if at+8+size > len(data):
                raise ValueError('Truncated GLB chunk')
            chunks[kind] = data[at+8:at+8+size]
            at += 8+size
        self.j = json.loads(chunks[0x4E4F534A])
        self.binary = chunks[0x004E4942]
        self.parents = {}
        for i, node in enumerate(self.j['nodes']):
            for child in node.get('children', []):
                if child in self.parents:
                    raise ValueError('Node has multiple parents')
                self.parents[child] = i
        self.worlds = {}

    def accessor(self, index):
        a = self.j['accessors'][index]
        if 'sparse' in a:
            raise ValueError('Sparse GLB accessors require expansion')
        v = self.j['bufferViews'][a['bufferView']]
        if v.get('buffer', 0):
            raise ValueError('External GLB buffers unsupported')
        dtype = {5120:'i1',5121:'u1',5122:'<i2',5123:'<u2',5125:'<u4',5126:'<f4'}[a['componentType']]
        components = {'SCALAR':1,'VEC2':2,'VEC3':3,'VEC4':4,'MAT4':16}[a['type']]
        size = np.dtype(dtype).itemsize
        offset = v.get('byteOffset',0)+a.get('byteOffset',0)
        stride = v.get('byteStride',size*components)
        if a['count'] and offset+(a['count']-1)*stride+components*size > v.get('byteOffset',0)+v['byteLength']:
            raise ValueError('GLB accessor exceeds buffer view')
        out = np.ndarray((a['count'],components),dtype=dtype,buffer=self.binary,
                         offset=offset,strides=(stride,size)).copy()
        if a.get('normalized') and a['componentType'] != 5126:
            maximum = np.iinfo(out.dtype).max
            out = np.maximum(out.astype(float)/maximum,-1)
        if not np.isfinite(out).all():
            raise ValueError('Nonfinite GLB attribute')
        return out

    def world(self, index):
        if index not in self.worlds:
            n = self.j['nodes'][index]
            if 'matrix' in n:
                m = np.array(n['matrix']).reshape(4,4).T
            else:
                m = np.eye(4)
                m[:3,:3] = rotation(n.get('rotation',[0,0,0,1])) @ np.diag(n.get('scale',[1,1,1]))
                m[:3,3] = n.get('translation',[0,0,0])
            self.worlds[index] = self.world(self.parents[index]) @ m if index in self.parents else m
        return self.worlds[index]


def mapping(name, target, source_kind):
    if name in target:
        return name
    aliases = {
        'root':'tag_origin', 'pelvis':'j_mainroot', 'spine1':'j_spinelower',
        'spine2':'j_spine4', 'neck':'j_neck', 'head':'j_head',
    }
    if source_kind == 'nicky':
        for side, code in [('l','le'),('r','ri')]:
            for original, native in [('clavicle','clavicle'),('upperarm','shoulder'),
                                     ('forearm','elbow'),('hand','wrist'),
                                     ('thigh','hip'),('calf','knee'),('foot','ankle'),('toe','ball')]:
                aliases[f'{original}_{side}'] = f'j_{native}_{code}'
            for original, native in [('index','index'),('middle','mid'),('ring','ring'),
                                     ('pinky','pinky'),('thumb','thumb')]:
                for phalanx in range(1,4):
                    aliases[f'{original}{phalanx}_{side}'] = f'j_{native}_{code}_{phalanx}'
    candidate = aliases.get(name)
    return candidate if candidate in target else None


def bone_worlds(donor):
    # baseMat is the native model-space bind pose consumed by the skin matrices.
    result=[]
    for bind in donor['skeleton']['baseMat']:
        m=np.eye(4)
        m[:3,:3]=rotation(bind['quat'])
        m[:3,3]=bind['trans']
        result.append(m)
    return np.array(result)


def align_directions(source,target):
    source=source/np.linalg.norm(source); target=target/np.linalg.norm(target)
    cross=np.cross(source,target); cosine=float(np.clip(np.dot(source,target),-1,1))
    if cosine>1-1e-10: return np.eye(3)
    if cosine<-1+1e-10:
        axis=np.cross(source,[0,0,1] if abs(source[2])<.9 else [0,1,0])
        axis/=np.linalg.norm(axis)
        return 2*np.outer(axis,axis)-np.eye(3)
    skew=np.array([[0,-cross[2],cross[1]],[cross[2],0,-cross[0]],[-cross[1],cross[0],0]])
    return np.eye(3)+skew+skew@skew/(1+cosine)


def anatomical_frame(forward, normal):
    forward = forward / np.linalg.norm(forward)
    side = np.cross(normal, forward)
    if np.linalg.norm(side) < 1e-8:
        return None
    side /= np.linalg.norm(side)
    return np.column_stack((forward, side, np.cross(forward, side)))


def prune_skeleton(model,retain_native_body=False):
    names=model['boneNames']; skeleton=model['skeleton']; roots=model['numRootBones']
    regular=model['numBones']
    def ancestors(bones):
        result=set(bones)
        for bone in tuple(result):
            while bone>=roots:
                bone-=skeleton['parentList'][bone-roots]
                result.add(bone)
        return result
    surface_bones=[]
    for surface in model['surfaces']:
        used=set(); cursor=0
        for tier,count in enumerate(surface['blendCounts']):
            for _ in range(count):
                words=surface['blendWords'][cursor:cursor+tier*2+1]
                used.update(words[index]//64 for index in (0,*range(1,len(words),2)))
                cursor+=tier*2+1
        if cursor!=len(surface['blendWords']):
            raise ValueError('Blend stream does not match the declared tiers')
        surface_bones.append(ancestors(used))
    # The body owns unweighted native attachment, IK and procedural tags too.
    # Preserve that complete native contract; the separate head needs only its
    # influenced bones and their ancestor closure.
    retained=(list(range(len(names))) if retain_native_body
              else sorted(set().union(*surface_bones)))
    remap={old:new for new,old in enumerate(retained)}
    new_roots=sum(old<roots for old in retained)
    new_regular=sum(old<regular for old in retained)
    new_skeleton={key:[skeleton[key][old] for old in retained]
                  for key in ('baseMat','boneInfo')}
    new_skeleton['partClassification']=[skeleton['partClassification'][old]
                                        for old in retained if old<regular]
    new_skeleton.update(parentList=[],quats=[],trans=[])
    for old in retained:
        if old<roots: continue
        parent=old-skeleton['parentList'][old-roots]
        distance=remap[old]-remap[parent]
        if not 1<=distance<=255:
            raise ValueError('Pruned parent is outside the native relative-byte range')
        new_skeleton['parentList'].append(distance)
        new_skeleton['quats'].append(skeleton['quats'][old-roots])
        new_skeleton['trans'].append(skeleton['trans'][old-roots])
    for surface,used in zip(model['surfaces'],surface_bones):
        cursor=0
        for tier,count in enumerate(surface['blendCounts']):
            for _ in range(count):
                for index in (0,*range(1,tier*2+1,2)):
                    old=surface['blendWords'][cursor+index]//64
                    surface['blendWords'][cursor+index]=remap[old]*64
                    if names[old]!=names[retained[surface['blendWords'][cursor+index]//64]]:
                        raise ValueError('Pruning changed a skin influence identity')
                cursor+=tier*2+1
        bits=[0]*8
        for old in used:
            new=remap[old]
            if new<254:
                bits[new//32]|=0x80000000>>(new%32)
            if new>=new_regular:
                bits[7]|=2
        surface['partBits']=bits
    model['boneNames']=[names[old] for old in retained]
    model['numRootBones']=new_roots
    model['numBones']=new_regular
    model['numClientBones']=len(retained)-new_regular
    model['skeleton']=new_skeleton
    return {'original_bones':len(names),'retained_bones':len(retained),
            'retained_native_indices':retained,'retained_names':model['boneNames'],
            'complete_native_body_retained':retain_native_body,
            'native_bind_arrays_preserved':True,'skin_influence_names_and_weights_preserved':True}


def prepare(args):
    source=Glb(args.source)
    donor=json.loads(args.native_skeleton.read_text())
    target=donor['boneNames']
    regular=donor['numBones']
    if not 0<regular<=254 or len(target)>768 or len(target)!=len(set(target)):
        raise ValueError('Target skeleton exceeds native regular/client bone limits')
    if len(target)!=regular+donor['numClientBones']:
        raise ValueError('Target skeleton count mismatch')
    target_world=bone_worlds(donor)
    if 'j_head' not in target or 'j_mainroot' not in target:
        raise ValueError('Native humanoid bind skeleton is missing mainroot/head')
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=True)
    # GLB world is Y-up. BO2 keeps X forward, -Z left. Nicky faces +Z,
    # and its named left limbs extend along +X.
    coordinate=np.eye(4)
    coordinate[:3,:3]=([[0,0,1],[1,0,0],[0,1,0]] if args.kind=='nicky'
                           else [[1,0,0],[0,0,-1],[0,1,0]])
    models={part:{'name':f'dw_operator_{args.id}_{part}','boneNames':target,
                  'numBones':regular,'numClientBones':donor['numClientBones'],
                  'numRootBones':donor['numRootBones'], 'skeleton':donor['skeleton'],
                  'surfaces':[]} for part in ('body','head')}
    if donor.get('physicsAssetName'):
        models['body']['physicsAssetName']=donor['physicsAssetName']
    materials={}
    donor_material=json.loads(args.material_donor.read_text())
    proof={'schema':1,'source':str(args.source.resolve()),'source_sha256':digest(args.source),
           'native_skeleton':str(args.native_skeleton.resolve()),
           'native_skeleton_sha256':digest(args.native_skeleton),
           'native_material_sha256':digest(args.material_donor),'bone_map':{},'surfaces':[],
           'validation':{'native_loader':False,'native_animation_runtime':False}}
    triangles_in=0
    for node_index,node in enumerate(source.j['nodes']):
        if 'mesh' not in node:
            continue
        if 'skin' not in node:
            raise ValueError('Operator primitive is unskinned')
        skin=source.j['skins'][node['skin']]
        joints=skin['joints']
        names=[source.j['nodes'][i].get('name',f'bone_{i}') for i in joints]
        source_world=np.array([coordinate@source.world(i) for i in joints])
        mesh_world=coordinate@source.world(node_index)
        inverse_bind=source.accessor(skin['inverseBindMatrices']).reshape(-1,4,4).transpose(0,2,1)
        if len(inverse_bind)!=len(joints):
            raise ValueError('Inverse bind count differs from skin joints')
        bind_error=float(max(np.max(np.abs(world@inverse-mesh_world))
                             for world,inverse in zip(source_world,inverse_bind)))
        if bind_error>(.0001 if args.kind=='nicky' else .02):
            raise ValueError(f'Source scene differs from inverse bind pose by {bind_error}')
        proof['source_bind_max_error']=max(proof.get('source_bind_max_error',0),bind_error)
        # Use the skin's exact bind matrix; exported local rotations may be rounded.
        source_world=np.array([mesh_world@np.linalg.inv(inverse) for inverse in inverse_bind])
        bind_by_node=dict(zip(joints,source_world))
        mapped=[]; mapped_source=[]; mapped_nodes=[]
        for bone,name in enumerate(names):
            resolved=mapping(name,target,args.kind)
            current=joints[bone]
            while resolved is None and current in source.parents:
                current=source.parents[current]
                resolved=mapping(source.j['nodes'][current].get('name',''),target,args.kind)
            if resolved is None:
                raise ValueError(f'Cannot map source joint {name} to native humanoid')
            mapped.append(target.index(resolved))
            mapped_source.append(bind_by_node.get(current,coordinate@source.world(current)))
            mapped_nodes.append(current)
            proof['bone_map'][name]=resolved
        source_head=names.index('head' if args.kind=='nicky' else 'j_head')
        source_height=source_world[source_head,2,3]-min(source_world[:,2,3])
        target_height=target_world[target.index('j_head'),2,3]-min(target_world[:,2,3])
        if source_height<=0 or target_height<=0:
            raise ValueError('Cannot determine positive native/source standing height')
        scale=args.scale if args.scale else target_height/source_height
        proof['residual_scale']=float(scale)
        endpoints={'tag_origin':'j_mainroot','j_mainroot':'j_spinelower',
                   'j_spinelower':'j_spineupper','j_spineupper':'j_neck',
                   'j_spine4':'j_neck','j_neck':'j_head'}
        for side in ('le','ri'):
            for chain in [('clavicle','shoulder','elbow','wrist'),('hip','knee','ankle','ball')]:
                for first,second in zip(chain,chain[1:]):
                    endpoints[f'j_{first}_{side}']=f'j_{second}_{side}'
            endpoints[f'j_wrist_{side}']=f'j_mid_{side}_1'
            for finger in ('thumb','index','mid','ring','pinky'):
                for first in (1,2):
                    endpoints[f'j_{finger}_{side}_{first}']=f'j_{finger}_{side}_{first+1}'
        source_by_target={}
        for i,name in enumerate(names):
            direct=mapping(name,target,args.kind)
            if direct is not None:
                source_by_target.setdefault(direct,i)
        if 'j_spineupper' not in source_by_target and 'j_spine4' in source_by_target:
            endpoints['j_spinelower']='j_spine4'
        palms = {}
        for side in ('le', 'ri'):
            names_for_palm = [f'j_wrist_{side}', f'j_index_{side}_1', f'j_pinky_{side}_1']
            if all(name in source_by_target and name in target for name in names_for_palm):
                source_points = [source_world[source_by_target[name], :3, 3] for name in names_for_palm]
                target_points = [target_world[target.index(name), :3, 3] for name in names_for_palm]
                normals = [np.cross(points[1]-points[0], points[2]-points[0])
                           for points in (source_points, target_points)]
                if min(map(np.linalg.norm, normals)) > 1e-8:
                    palms[side] = normals
        bind_transforms=[]
        for i,tgt in enumerate(mapped):
            origin=mapped_source[i][:3,3]
            native_origin=target_world[tgt][:3,3]
            next_name=endpoints.get(target[tgt])
            direction=None
            if next_name in source_by_target and next_name in target:
                source_end=source_world[source_by_target[next_name],:3,3]
                native_end=target_world[target.index(next_name),:3,3]
                direction=(source_end-origin,native_end-native_origin)
            if direction is None or min(map(np.linalg.norm,direction))<1e-6:
                parent=mapped_nodes[i]
                while parent in source.parents:
                    parent=source.parents[parent]
                    parent_name=mapping(source.j['nodes'][parent].get('name',''),target,args.kind)
                    if parent_name and parent_name!=target[tgt]:
                        source_parent=bind_by_node.get(parent,coordinate@source.world(parent))[:3,3]
                        native_parent=target_world[target.index(parent_name),:3,3]
                        candidate=(origin-source_parent,native_origin-native_parent)
                        if min(map(np.linalg.norm,candidate))>1e-6:
                            direction=candidate
                            break
            alignment=(align_directions(*direction) if direction is not None
                       and min(map(np.linalg.norm,direction))>1e-6 else np.eye(3))
            bone_scale = scale
            hand_side = next((side for side in palms if target[tgt] == f'j_wrist_{side}' or
                any(target[tgt].startswith(f'j_{finger}_{side}_')
                    for finger in ('thumb', 'index', 'mid', 'ring', 'pinky'))), None)
            if hand_side and direction is not None and min(map(np.linalg.norm,direction)) > 1e-6:
                source_frame = anatomical_frame(direction[0], palms[hand_side][0])
                target_frame = anatomical_frame(direction[1], palms[hand_side][1])
                if source_frame is None or target_frame is None:
                    raise ValueError('Degenerate hand frame: ' + name)
                alignment = target_frame @ source_frame.T
                bone_scale = np.linalg.norm(direction[1]) / np.linalg.norm(direction[0])
                before = align_directions(*direction) * scale @ direction[0]
                after = alignment * bone_scale @ direction[0]
                error = float(np.linalg.norm(after-direction[1]))
                if error > 1e-6 or np.linalg.det(alignment) < 0.999999:
                    raise ValueError('Invalid anatomical hand retarget: ' + name)
                proof.setdefault('hand_frames', {})[names[i]] = dict(
                    target=target[tgt], native_length=float(np.linalg.norm(direction[1])),
                    source_length=float(np.linalg.norm(direction[0])), scale=float(bone_scale),
                    old_endpoint_error=float(np.linalg.norm(before-direction[1])), endpoint_error=error,
                    old_palm_normal_dot=float(np.dot(align_directions(*direction) @ source_frame[:,2], target_frame[:,2])),
                    palm_normal_dot=float(np.dot(alignment @ source_frame[:,2], target_frame[:,2])))
            # Source rigs use different local joint axes. Align anatomical bind
            # directions in model space, then bind the result to native matrices.
            transform=np.eye(4)
            transform[:3,:3]=alignment*bone_scale
            transform[:3,3]=native_origin-transform[:3,:3]@origin
            bind_transforms.append(transform)
        bind_transforms=np.array(bind_transforms)
        for primitive in source.j['meshes'][node['mesh']]['primitives']:
            if primitive.get('mode',4)!=4:
                raise ValueError('Only triangular skinned primitives supported')
            a=primitive['attributes']
            pos=source.accessor(a['POSITION']).astype(float)
            normal=source.accessor(a['NORMAL']).astype(float)
            uv=source.accessor(a['TEXCOORD_0']).astype(float)
            joint=source.accessor(a['JOINTS_0']).astype(int)
            weight=source.accessor(a['WEIGHTS_0']).astype(float)
            if 'JOINTS_1' in a or 'WEIGHTS_1' in a:
                raise ValueError('More than four source influences requires audited reduction')
            indices=source.accessor(primitive['indices']).reshape(-1).astype(int)
            if len(indices)%3 or np.any(indices<0) or np.any(indices>=len(pos)):
                raise ValueError('Invalid source triangle indices')
            triangles_in+=len(indices)//3
            used_input,indices=np.unique(indices,return_inverse=True)
            pos=pos[used_input]; normal=normal[used_input]; uv=uv[used_input]
            joint=joint[used_input]; weight=weight[used_input]
            pos=np.c_[pos,np.ones(len(pos))]@mesh_world.T
            normal=normal@np.linalg.inv(mesh_world[:3,:3])
            native_pos=np.zeros((len(pos),3))
            native_normal=np.zeros((len(pos),3))
            weights=[]
            for i in range(len(pos)):
                w=weight[i]
                if np.any(w<0) or w.sum()<1e-8 or np.any(joint[i]>=len(joints)):
                    raise ValueError('Invalid source skin influence')
                w=w/w.sum()
                merged={}
                for b,influence in zip(joint[i],w):
                    if influence<=0: continue
                    native_pos[i]+=(bind_transforms[b]@pos[i])[:3]*influence
                    # Uniform residual scale does not affect the normalized normal.
                    native_normal[i]+=(np.linalg.inv(bind_transforms[b][:3,:3]).T@normal[i])*influence
                    merged[mapped[b]]=merged.get(mapped[b],0)+float(influence)
                influences=sorted(merged.items(),key=lambda pair:(-pair[1],pair[0]))
                weights.append(influences)
            native_normal/=np.linalg.norm(native_normal,axis=1)[:,None]
            tangents=np.zeros_like(native_normal); bitangents=np.zeros_like(native_normal)
            for triangle in indices.reshape(-1,3):
                first,second,third=triangle
                edge1=native_pos[second]-native_pos[first]
                edge2=native_pos[third]-native_pos[first]
                delta1=uv[second]-uv[first]; delta2=uv[third]-uv[first]
                denominator=delta1[0]*delta2[1]-delta1[1]*delta2[0]
                if abs(denominator)<1e-12: continue
                tangent=(edge1*delta2[1]-edge2*delta1[1])/denominator
                bitangent=(edge2*delta1[0]-edge1*delta2[0])/denominator
                for vertex in triangle:
                    tangents[vertex]+=tangent; bitangents[vertex]+=bitangent
            material_index=primitive.get('material',0)
            source_material=source.j.get('materials',[{}])[material_index]
            material_name=f'w/mw120r_mp_operator_{args.id}_{material_index}'
            if material_name not in materials:
                m=json.loads(json.dumps(donor_material))
                m['name']=material_name
                image_name=f'dw_operator_{args.id}_color_{material_index}'
                texture_index=source_material.get('pbrMetallicRoughness',{}).get('baseColorTexture',{}).get('index')
                if texture_index is None:
                    raise ValueError('Source material lacks diffuse image')
                image_index=source.j['textures'][texture_index]['source']
                image=source.j['images'][image_index]
                if 'uri' in image:
                    texture=Image.open(args.source.parent/image['uri']).convert('RGBA')
                else:
                    import io
                    view=source.j['bufferViews'][image['bufferView']]
                    at=view.get('byteOffset',0)
                    texture=Image.open(io.BytesIO(source.binary[at:at+view['byteLength']])).convert('RGBA')
                pixels=f'{args.id}_color_{material_index}.rgba'
                (output/pixels).write_bytes(texture.tobytes())
                color_slots=args.color_slot if args.color_slot is not None else m.get('colorSlots',[0])
                for slot in color_slots:
                    m['textures'][slot]['image']=image_name
                m['images']=[{'name':image_name,'width':texture.width,'height':texture.height,
                              'pixels':pixels,'format':7,'semantic':1}]
                materials[material_name]=m
            triangles=indices.reshape(-1,3)
            is_head=np.array([sum(w for b,w in influences if target[b] in ('j_head','j_neck'))>0.5 for influences in weights])
            partitions={'head':triangles[np.sum(is_head[triangles],axis=1)>=2],
                        'body':triangles[np.sum(is_head[triangles],axis=1)<2]}
            # Shared source indices retain identical transformed positions at the seam.
            for part,triangles in partitions.items():
                if not len(triangles): continue
                used=np.unique(triangles)
                used=sorted(used.tolist(),key=lambda i:(len(weights[i]),i))
                if len(used)>32767:
                    raise ValueError('Primitive exceeds signed per-blend-tier count')
                remap={old:new for new,old in enumerate(used)}
                verts=[]; blend_counts=[0]*4; blend_words=[]; bits=[0]*8
                for old in used:
                    influences=weights[old]
                    blend_counts[len(influences)-1]+=1
                    # First influence is the implicit remainder after explicit weights.
                    explicit=[int(round(w*65535)) for _,w in influences[1:]]
                    if sum(explicit)>65535:
                        explicit[-1]-=sum(explicit)-65535
                    blend_words.append(influences[0][0]*64)
                    for (bone,_),w in zip(influences[1:],explicit):
                        blend_words.extend([bone*64,w])
                    for bone,_ in influences:
                        while True:
                            if bone<254:
                                bits[bone//32]|=0x80000000>>(bone%32)
                            if bone>=regular:
                                bits[7]|=2
                            if bone<donor['numRootBones']: break
                            bone-=donor['skeleton']['parentList'][bone-donor['numRootBones']]
                    n=native_normal[old]
                    tangent=tangents[old]-n*np.dot(n,tangents[old])
                    if np.linalg.norm(tangent)<1e-10:
                        tangent=np.cross([0,0,1] if abs(n[2])<.9 else [0,1,0],n)
                    tangent/=np.linalg.norm(tangent)
                    sign=-1 if np.dot(np.cross(n,tangent),bitangents[old])<0 else 1
                    verts.append({'position':native_pos[old].tolist(),'normal':n.tolist(),
                                  'tangent':tangent.tolist(),'uv':uv[old].tolist(),'sign':sign})
                # Replay's native front faces have the opposite winding to glTF.
                surface={'material':material_name,'vertices':verts,'indices':[remap[int(i)] for i in triangles[:,[0,2,1]].reshape(-1)],
                         'blendCounts':blend_counts,'blendWords':blend_words,'partBits':bits}
                models[part]['surfaces'].append(surface)
                proof['surfaces'].append({'part':part,'source_material':source_material.get('name'),
                                          'vertices':len(used),'triangles':len(triangles),
                                          'blendCounts':blend_counts})
    for part,model in models.items():
        model['skeleton']=json.loads(json.dumps(model['skeleton']))
        positions=np.array([v['position'] for s in model['surfaces'] for v in s['vertices']])
        if not len(positions):
            raise ValueError(f'No {part} triangles after native head/body separation')
        model['minimum']=positions.min(axis=0).tolist(); model['maximum']=positions.max(axis=0).tolist()
        # The native GPU writes animated positions into this same packed range.
        # Match the shipped skeleton's origin-centered animation envelope and
        # enlarge it for geometry that extends beyond the donor's proportions.
        extent=max(max(donor['boundsHalf']),float(np.max(np.linalg.norm(positions,axis=1)))*1.5)
        model['skinBounds']={'midPoint':[0,0,0],'halfSize':[extent]*3}
        # Native per-bone bounds enclose this model's actual retargeted vertices.
        points=[[] for _ in target]
        for surface in model['surfaces']:
            cursor=0; vertex=0
            for tier,count in enumerate(surface['blendCounts']):
                for _ in range(count):
                    words=surface['blendWords'][cursor:cursor+tier*2+1]
                    for word in [0,*range(1,len(words),2)]:
                        bone=words[word]//64
                        position=np.r_[surface['vertices'][vertex]['position'],1]
                        points[bone].append((np.linalg.inv(target_world[bone])@position)[:3])
                    vertex+=1; cursor+=tier*2+1
        for bone,values in enumerate(points):
            if values:
                values=np.array(values); low=values.min(axis=0); high=values.max(axis=0)
                middle=(low+high)*.5; half=(high-low)*.5
                model['skeleton']['boneInfo'][bone]={'midPoint':middle.tolist(),'halfSize':half.tolist(),
                                                    'radiusSquared':float(np.dot(half,half))}
    proof['skeleton_pruning']={part:prune_skeleton(model,retain_native_body=part=='body')
                               for part,model in models.items()}
    proof['raw_head_body_bones']=sum(model['numBones'] for model in models.values())
    proof['remaining_native_regular_bone_budget']=254-proof['raw_head_body_bones']
    if proof['remaining_native_regular_bone_budget']<0:
        raise ValueError('Head/body exceeds the native raw regular-bone limit before deduplication')
    total=sum(s['triangles'] for s in proof['surfaces'])
    if total!=triangles_in:
        raise ValueError('Head/body split changed triangle coverage')
    proof['triangles_in']=triangles_in; proof['triangles_out']=total
    package={'schema':1,'materials':list(materials.values()),'models':list(models.values())}
    (output/'model-input.json').write_text(json.dumps(package,separators=(',',':'))+'\n')
    (output/'import-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'output':str(output),'triangles':total,'native_donor_bones':len(target),
                      'models':[{'name':m['name'],'bones':len(m['boneNames'])} for m in models.values()],
                      'raw_head_body_bones':proof['raw_head_body_bones']},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--native-skeleton',type=Path,required=True)
    p.add_argument('--material-donor',type=Path,required=True)
    p.add_argument('--kind',choices=['nicky','cod'],required=True)
    p.add_argument('--id',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--scale',type=float)
    p.add_argument('--color-slot',type=int,action='append')
    prepare(p.parse_args())

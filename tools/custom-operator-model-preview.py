"""Render a bind-pose geometry check; this is not native runtime evidence."""
import json
from pathlib import Path
from PIL import Image,ImageDraw
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
output=ROOT/'data/custom-operators/bind-pose-preview.png'
canvas=Image.new('RGB',(1600,1100),(28,31,37))
draw=ImageDraw.Draw(canvas)
for model_index,identity in enumerate(('nicky','bo2')):
    directory=ROOT/'data/custom-operators'/identity/'native'
    value=json.loads((directory/'model-input.json').read_text())
    textures={}
    for m in value['materials']:
        im=m['images'][0]
        textures[m['name']]=np.array(Image.frombytes('RGBA',(im['width'],im['height']),
                                                   (directory/im['pixels']).read_bytes()))
    for view,(horizontal,depth) in enumerate(((1,0),(0,1))):
        panel=model_index*800+view*400
        triangles=[]
        for model in value['models']:
            for surf in model['surfaces']:
                positions=np.array([v['position']for v in surf['vertices']])
                uvs=np.array([v['uv']for v in surf['vertices']])
                tex=textures[surf['material']]
                for tri in np.array(surf['indices']).reshape(-1,3):
                    p=positions[tri]; uv=np.mean(uvs[tri],axis=0)%1
                    color=tex[min(int(uv[1]*tex.shape[0]),tex.shape[0]-1),
                              min(int(uv[0]*tex.shape[1]),tex.shape[1]-1),:3].astype(float)
                    normal=np.cross(p[1]-p[0],p[2]-p[0]);length=np.linalg.norm(normal)
                    shade=.6+.4*abs(normal[depth])/length if length else .6
                    color=tuple((color*shade).astype(int))
                    points=[(panel+200+(-1 if horizontal==1 else 1)*float(q[horizontal])*8,
                             970-float(q[2])*11)for q in p]
                    triangles.append((float(np.mean(p[:,depth])),points,color))
        for _,points,color in sorted(triangles,key=lambda t:t[0]):
            draw.polygon(points,fill=color)
        draw.line((panel+20,971,panel+380,971),fill=(90,94,100))
        draw.text((panel+30,1010),identity.upper()+(' - FRONT' if view==0 else ' - SIDE'),fill='white')
draw.text((25,25),'Imported bind geometry on the native Replay human skeleton. Native animation and materials require game testing.',fill='white')
canvas.save(output)
print(output)

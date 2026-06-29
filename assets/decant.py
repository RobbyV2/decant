import numpy as np, math, sys, gc
from scipy.interpolate import PchipInterpolator
from PIL import Image, ImageFilter, ImageDraw

PPU = int(sys.argv[2]) if len(sys.argv)>2 else 380
SS  = int(sys.argv[1]) if len(sys.argv)>1 else 1

ctrl = [
 (0.000,0.820),(0.050,0.860),(0.120,0.920),(0.220,0.972),(0.340,1.000),
 (0.470,0.972),(0.610,0.886),(0.750,0.748),(0.880,0.585),(1.000,0.462),
 (1.150,0.372),(1.320,0.326),(1.480,0.318),(1.620,0.345),(1.740,0.395),
 (1.840,0.448),(1.920,0.488),(2.020,0.518),(2.120,0.532),(2.220,0.534),(2.260,0.535)
]
cy=np.array([c[0] for c in ctrl]); cr=np.array([c[1] for c in ctrl])
fr=PchipInterpolator(cy,cr)
ymin_g,ymax_g=0.0,2.260; M=4000
yg=np.linspace(ymin_g,ymax_g,M)
rg_out=fr(yg).astype(np.float32)
dy=(ymax_g-ymin_g)/(M-1); sl_out=np.gradient(rg_out,dy).astype(np.float32)
WALL=0.060
rg_in=np.clip(rg_out-WALL,1e-4,None).astype(np.float32)
sl_in=np.gradient(rg_in,dy).astype(np.float32)

Y_IN_BOT=0.17; Y_OUT_BOT=0.0; Y_TOP=2.22; Y_WINE=0.560
P0=np.array([0.0,1.80,0.0],np.float32)
N =np.array([-0.12,1.0,0.56],np.float32); N/=np.linalg.norm(N)
KRIM=0.032

L=np.array([-0.5,0.70,0.55],np.float32); L/=np.linalg.norm(L)
L2=np.array([0.7,0.2,0.5],np.float32); L2/=np.linalg.norm(L2)
Vv=np.array([0,0,1],np.float32); Hh=L+Vv; Hh/=np.linalg.norm(Hh)

def gather(y,grid):
    f=(y-ymin_g)/(ymax_g-ymin_g)*(M-1)
    i=np.clip(np.floor(f),0,M-2).astype(np.int32); g=np.clip(f-i,0,1)
    return grid[i]*(1-g)+grid[i+1]*g
def smin(a,b,k):
    h=np.clip(0.5+0.5*(b-a)/k,0,1); return b*(1-h)+a*h-k*h*(1-h)
def smax(a,b,k): return -smin(-a,-b,k)

def comps(P):
    x=P[...,0]; y=P[...,1]; z=P[...,2]; rad=np.sqrt(x*x+z*z)
    ro=gather(y,rg_out); so=gather(y,sl_out); ri=gather(y,rg_in); si=gather(y,sl_in)
    d_out=(rad-ro)/np.sqrt(1+so*so); d_in=(rad-ri)/np.sqrt(1+si*si)
    S_out=np.maximum.reduce([d_out, y-Y_TOP, Y_OUT_BOT-y])
    S_in =np.maximum.reduce([d_in,  y-(Y_TOP+0.2), Y_IN_BOT-y])
    S_shell=smax(S_out,-S_in,0.012)
    pl=(x-P0[0])*N[0]+(y-P0[1])*N[1]+(z-P0[2])*N[2]
    S_glass=smax(S_shell,pl,KRIM)
    S_wine=np.maximum.reduce([d_in, y-Y_WINE, Y_IN_BOT-y])
    return S_out,S_in,pl,S_glass,S_wine
def sdf(P):
    _,_,_,g,wsd=comps(P); return np.minimum(g,wsd)

xmin,xmax=-1.16,1.16; ymin_v,ymax_v=-0.15,2.25
Wpx=int(round(PPU*(xmax-xmin)))*SS
Hpx=int(round(PPU*(ymax_v-ymin_v)))*SS
z0=1.9; D=np.array([0,0,-1],np.float32); TMAX=3.9; NST=90

def fill(big,Wpx,Hpx):
    xs=np.linspace(xmin,xmax,Wpx,dtype=np.float32)
    strip=max(SS,(Hpx//24))
    for r0 in range(0,Hpx,strip):
        r1=min(Hpx,r0+strip)
        ys=(ymax_v-(np.arange(r0,r1)+0.5)/Hpx*(ymax_v-ymin_v)).astype(np.float32)
        WX,WY=np.meshgrid(xs,ys)
        wx=WX.ravel().astype(np.float32); wy=WY.ravel().astype(np.float32); Npix=wx.size
        rout=gather(wy,rg_out)
        possible=np.abs(wx)<=rout+0.03
        z_enter=np.sqrt(np.maximum(rout*rout-wx*wx,0.0)).astype(np.float32)
        t=np.where(possible,(z0-z_enter-0.03).astype(np.float32),np.float32(TMAX))
        active=possible.copy()
        for _ in range(80):
            if not active.any(): break
            ai=np.where(active)[0]; z=z0-t[ai]
            pts=np.stack([wx[ai],wy[ai],z],axis=-1); sv=sdf(pts)
            t[ai]=t[ai]+sv*0.85; zn=z0-t[ai]
            done=(sv<1.2e-3)|(t[ai]>=TMAX)|(zn< -(rout[ai]+0.06))
            active[ai[done]]=False
        z=z0-t; P=np.stack([wx,wy,z],axis=-1)
        s=sdf(P); hit=(s<2e-3)&possible
        e=np.float32(1.0e-3)
        ex=np.array([e,0,0],np.float32); ey=np.array([0,e,0],np.float32); ez=np.array([0,0,e],np.float32)
        nx=sdf(P+ex)-sdf(P-ex); ny=sdf(P+ey)-sdf(P-ey); nz=sdf(P+ez)-sdf(P-ez)
        nl=np.sqrt(nx*nx+ny*ny+nz*nz)+1e-9; nx/=nl; ny/=nl; nz/=nl
        so,si,pl,g,wsd=comps(P)
        is_wine=(wsd<g); a_out=so; a_in=-si
        is_inner=(~is_wine)&(a_in>a_out)&(a_in>pl)
        diff=np.clip(nx*L[0]+ny*L[1]+nz*L[2],0,1)
        diff2=np.clip(nx*L2[0]+ny*L2[1]+nz*L2[2],0,1)
        ndh=np.clip(nx*Hh[0]+ny*Hh[1]+nz*Hh[2],0,1); spec=ndh**46
        fres=np.clip(1-np.clip(nz,0,1),0,1)**3
        Y=wy
        wlev=Y_WINE+0.035*np.sin(wx*5.0+0.6)
        below=Y<wlev
        redalb=np.array([150,22,26],np.float32)[None,:]*(0.55+0.45*np.clip(Y/Y_WINE,0,1))[:,None]
        whitealb=np.array([233,237,242],np.float32)
        galb=np.where(below[:,None],redalb,whitealb[None,:])
        glass=galb*(0.37+0.63*diff)[:,None]+galb*0.06*diff2[:,None]+255*(0.30*spec)[:,None]+255*(0.12*fres)[:,None]
        hl=(42*np.exp(-(((wx+0.50)/0.16)**2+((wy-0.78)/0.32)**2))
            +78*np.exp(-(((wx+0.58-0.13*((wy-0.92)/0.3)**2)/0.05)**2+((wy-0.92)/0.32)**2)))
        glass=glass+hl[:,None]
        men=np.exp(-((Y-wlev)/0.013)**2); glass=glass+(men*55)[:,None]
        depth=np.clip((1.95-Y)/1.6,0,1)
        inn=np.array([130,136,148],np.float32)[None,:]*(0.16+0.62*diff)[:,None]
        inn=inn*(1-0.55*depth)[:,None]
        inn=inn+np.array([70,10,12],np.float32)[None,:]*0.5*np.clip(depth-0.4,0,1)[:,None]
        wine=np.array([120,12,18],np.float32)[None,:]*(0.45+0.7*diff)[:,None]+255*(0.45*spec)[:,None]
        col=glass.copy()
        col=np.where(is_inner[:,None],inn,col)
        col=np.where(is_wine[:,None],wine,col)
        col=np.clip(col,0,255)
        band=np.zeros((Npix,4),np.float32); band[:,:3]=col; band[:,3]=np.where(hit,255,0)
        big[r0:r1]=band.reshape(r1-r0,Wpx,4).astype(np.uint8)
        del WX,WY,wx,wy,P,band,col,glass,nx,ny,nz; gc.collect()

big=np.zeros((Hpx,Wpx,4),np.uint8)
fill(big,Wpx,Hpx)
ves=Image.fromarray(big,'RGBA'); del big; gc.collect()
if SS>1: ves=ves.resize((Wpx//SS,Hpx//SS),Image.LANCZOS)
Wo,Ho=ves.size
ppo=Wo/(xmax-xmin)
bx=(0.0-xmin)/(xmax-xmin)*Wo; by=(ymax_v-0.0)/(ymax_v-ymin_v)*Ho
sh=Image.new('L',(Wo,Ho),0); ImageDraw.Draw(sh).ellipse(
   [bx-0.86*ppo, by-0.05*ppo, bx+0.86*ppo, by+0.07*ppo], fill=120)
sh=sh.filter(ImageFilter.GaussianBlur(0.05*ppo))
shadow=Image.merge('RGBA',(Image.new('L',(Wo,Ho),20),Image.new('L',(Wo,Ho),22),Image.new('L',(Wo,Ho),30),sh))
out=Image.alpha_composite(shadow,ves)
fa=np.asarray(out).astype(np.float32)
fa[...,:3]=np.clip(fa[...,:3]+(np.random.rand(Ho,Wo,1).astype(np.float32)-0.5)*1.6,0,255)
out=Image.fromarray(fa.astype(np.uint8),'RGBA')
out.save('/mnt/user-data/outputs/decant_logo.png')
Image.alpha_composite(Image.new('RGBA',out.size,(255,255,255,255)),out).convert('RGB').save('/home/claude/preview_white.png')
print('done SS=%d %dx%d'%(SS,out.size[0],out.size[1]))

/*Our Proposal
 *This is the element that manipulate cache mechanism
*/
#include "cacheunit.hh"

CLICK_DECLS

bool CacheEntry::matchIID(Vector<String>& fullIDs)
{
    String IID ;
    IID = fullIDs[0].substring(fullIDs[0].length() - PURSUIT_ID_LEN) ;//get the information ID
    String tempSID ;
    Vector<String> forSIDupdate ;
    Vector<String>::iterator input_iter ;
    Vector<String>::iterator SIDs_iter ;
    Vector<String>::iterator IID_iter ;
    bool ret = false ;
    bool updateSID = false ;
    for( input_iter = fullIDs.begin() ; input_iter != fullIDs.end() ; input_iter++)//for each input ID
    {
        tempSID = input_iter->substring(0, input_iter->length()-PURSUIT_ID_LEN) ;//get the Scope ID
        forSIDupdate.push_back(tempSID) ;
        for(SIDs_iter = SIDs.begin() ; SIDs_iter != SIDs.end() ; SIDs_iter++)//for each local cache Scope ID
        {
            if(!(tempSID.compare(*SIDs_iter)))
            {
                updateSID = true ;
                for(IID_iter = IIDs.begin() ; IID_iter != IIDs.end() ; IID_iter++)
                {
                    if( !(IID.compare(*IID_iter)))
                        ret = true ;
                }
            }
        }
    }
    if(updateSID == true)
        SIDs = forSIDupdate ;
    return ret ;
}

bool CacheEntry::matchSID(String SID)
{
    Vector<String>::iterator sid_iter ;
    for(sid_iter = SIDs.begin() ; sid_iter != SIDs.end() ; sid_iter++)
    {
        if(!(SID.compare(*sid_iter)))
        {
            return true ;
        }
    }
    return false ;
}

CacheUnit::CacheUnit(){}
CacheUnit::~CacheUnit(){click_chatter("CacheUnit: destroyed!");}

int CacheUnit::configure(Vector<String> &conf, ErrorHandler *errh)
{
    gc = (GlobalConf*) cp_element(conf[0], this) ;
    return 0 ;
}
int CacheUnit::initialize(ErrorHandler *errh)
{
    cache_size = 1024*1024*512 ; //512MB
    cache.clear() ;
    return 0 ;
}
void CacheUnit::cleanup(CleanupStage stage)
{

    if(stage >= CLEANUP_CONFIGURED)
    {
        for(int i = 0 ; i < cache.size() ; i++)
        {
            CacheEntry* ce = cache.at(i) ;
            ce->clean() ;
            delete ce ;
        }
    }
}
void CacheUnit::push(int port, Packet *p)
{
    BABitvector FID(FID_LEN*8) ;
    unsigned char numberOfIDs ;
    unsigned char IDLength /*in fragments of PURSUIT_ID_LEN each*/;
    unsigned char prefixIDLength /*in fragments of PURSUIT_ID_LEN each*/ ;
    Vector<String> IDs;
    Vector<CacheEntry*>::iterator cache_iter ;
    int index = 0 ;
    if(port == 0)//this is a probing message
    {
        int numberOfInfoIDs ;
        Vector<String> IIDs ;
        Vector<String>::iterator iiditer ;
        BABitvector BFforIID(PURSUIT_ID_LEN*8) ;
        unsigned char hop_count ;
        unsigned char origin ;
        int i = 0 ;
        IIDs.clear() ;
        if (gc->use_mac) {
            memcpy(FID._data, p->data() + 14, FID_LEN);
        } else {
            return ;//right now only support ethernet level
        }
        memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
        for (int i = 0; i < (int) numberOfIDs; i++) {
            IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
            IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                IDLength * PURSUIT_ID_LEN));
            index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
        }
        memcpy(&hop_count, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, sizeof(hop_count)) ;//assign hop_count
        memcpy(&origin, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count)+FID_LEN, sizeof(origin)) ;
        WritablePacket* packet = p->uniqueify() ;

        for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
        {
            if((*cache_iter)->matchIID(IDs))
            {
                hop_count = 0 ;//start from 0
                origin = 1 ;//origin is cache
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, &hop_count, sizeof(hop_count)) ;
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count), gc->iLID._data, FID_LEN) ;
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count)+FID_LEN, &origin, sizeof(origin)) ;
                output(0).push(packet) ;
                return ;
            }
        }
        hop_count++ ;
        memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, &hop_count, sizeof(hop_count)) ;
        packet->set_anno_u32(0, (uint32_t)(index+sizeof(numberOfIDs)+FID_LEN+14)) ;
        output(0).push(packet) ;
        /*this is for k-anycast
        for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)//search for scope ID match
        {
            if((*cache_iter)->matchSID(IDs))
            {
                IIDs = (*cache_iter)->IIDs ;//assign information ID
                break ;
            }
        }


        memcpy(BFforIID._data, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, PURSUIT_ID_LEN) ;
        memcpy(&numberOfInfoIDs, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+PURSUIT_ID_LEN,\
                sizeof(numberOfInfoIDs)) ;
        Vector<String> uniqueIIDs ;
        uniqueIIDs.clear() ;
        for(iiditer = IIDs.begin() ; iiditer != IIDs.end() ; iiditer++)//erase the information IDs that are already in the probing message
        {
            BABitvector tempbitvector(PURSUIT_ID_LEN*8) ;
            memcpy(tempbitvector._data, iiditer->c_str(), PURSUIT_ID_LEN) ;
            BABitvector testbitvector(PURSUIT_ID_LEN*8) ;
            testbitvector = BFforIID&tempbitvector ;
            if(testbitvector != tempbitvector)//not in the probing message
            {
                BFforIID = BFforIID|tempbitvector ;//update the bloom filter of informatino ID
                uniqueIIDs.push_back(*iiditer) ;
            }

        }
        if(!uniqueIIDs.empty())//if there are some new information IDs
        {
            numberOfInfoIDs += uniqueIIDs.size() ;
            int original_length ;
            original_length = p->length() ;
            WritablePacket *packet=p->put(uniqueIIDs.size()*PURSUIT_ID_LEN) ;
            memcpy(packet->data()+14+sizeof(numberOfIDs)+index+FID_LEN, BFforIID._data, PURSUIT_ID_LEN) ;//update the bloom filter
            memcpy(packet->data()+14+sizeof(numberOfIDs)+index+FID_LEN+PURSUIT_ID_LEN,\
                &numberOfInfoIDs, sizeof(numberOfInfoIDs)) ;
            for(iiditer = uniqueIIDs.begin() ; iiditer != uniqueIIDs.end() ; iiditer++)//add the new information ID
            {
                memcpy(packet->data()+original_length+i*PURSUIT_ID_LEN, iiditer->c_str(), PURSUIT_ID_LEN) ;
                i++ ;
            }
            output(0).push(packet) ;

            int packetsize = p->length()+uniqueIIDs.size()*PURSUIT_ID_LEN ;
            WritablePacket *packet = Packet::make(NULL, packetsize) ;
            numberOfInfoIDs += uniqueIIDs.size() ;
            memcpy(packet->data(), p->data, 14+sizeof(numberOfIDs)+index+FID_LEN) ;
            memcpy(packet->data()+14+sizeof(numberOfIDs)+index+FID_LEN, BFforIID._data, PURSUIT_ID_LEN) ;
            memcpy(packet->data()+14+sizeof(numberOfIDs)+index+FID_LEN+PURSUIT_ID_LEN,\
                &numberOfInfoIDs, sizeof(numberOfInfoIDs)) ;
            memcpy(packet->data()+14+sizeof(numberOfIDs)+index+FID_LEN+PURSUIT_ID_LEN+sizeof(numberOfInfoIDs),\
                   p->data()+14+sizeof(numberOfIDs)+index+FID_LEN+PURSUIT_ID_LEN+sizeof(numberOfInfoIDs),\
                   (numberOfInfoIDs-uniqueIIDs.size())*PURSUIT_ID_LEN) ;
            for(iiditer = uniqueIIDs.begin() ; iiditer != uniqueIIDs.end() ; iiditer++)
            {
                memcpy(packet->data()+p->length()+i*PURSUIT_ID_LEN, iiditer->c_str(), PURSUIT_ID_LEN) ;
                i++ ;
            }
            packet->set_anno_u32(0, (uint32_t)(index+sizeof(numberOfIDs)+FID_LEN+14)) ;
            p->kill() ;
            output(0).push(packet) ;*/
    }
    else if(port == 1)
    {
        /*this is a subinfo packet*/
        memcpy(FID._data, p->data()+14, FID_LEN) ;
        BABitvector testFID(FID_LEN*8) ;
        testFID = FID & gc->iLID ;
        if(testFID == gc->iLID)
        {
            bool cachefound = false ;
            BABitvector backFID(FID_LEN*8) ;
            memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
            for (int i = 0; i < (int) numberOfIDs; i++) {
                IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
                IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                    IDLength * PURSUIT_ID_LEN));
                index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
            }
            memcpy(backFID._data, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index, FID_LEN) ;

            for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
            {
                if((*cache_iter)->matchIID(IDs))
                {//local cache found
                    cachefound = true ;
                    int reverse_proto ;
                    int prototype ;
                    cp_integer(String("0x080d"), 16, &reverse_proto);
                    prototype = htons(reverse_proto);
                    WritablePacket* packet ;

                    String infoID = IDs[0].substring(IDs[0].length()-PURSUIT_ID_LEN, PURSUIT_ID_LEN) ;
                    if((*cache_iter)->_data_length[infoID] > FID_LEN+2*PURSUIT_ID_LEN)
                        packet = p->put((*cache_iter)->_data_length[infoID] - (FID_LEN+2*PURSUIT_ID_LEN)) ;
                    else
                    {
                        p->take((FID_LEN+2*PURSUIT_ID_LEN) - ((*cache_iter)->_data_length[infoID])) ;
                        packet = p->uniqueify() ;
                    }

                    memcpy(packet->data()+12, &prototype, 2) ;
                    memcpy(packet->data()+14, backFID._data, FID_LEN) ;
                    memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index, (*cache_iter)->_data[infoID],\
                           (*cache_iter)->_data_length[infoID]) ;
                    output(1).push(packet) ;
                    break ;
                }
            }
            if(!cachefound)
            {//if get here, it means that the local cache has been flushed, so the forwarder must redirect the xubinfo
            //request to the final publisher

                unsigned char type = PLEASE_PUSH_DATA ;
                unsigned char idno = 1 ;
                unsigned char iidlen = 2 ;
                String notificationIID ;
                Vector<String>::iterator vec_str_iter ;
                int total_ID_length = 0 ;
                int packet_len ;
                int IDindex = 0 ;
                WritablePacket* packet ;

                notificationIID = String((const char*)(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN),\
                                         iidlen*PURSUIT_ID_LEN) ;
                for( vec_str_iter = IDs.begin() ; vec_str_iter != IDs.end() ; vec_str_iter++)
                {
                    total_ID_length += vec_str_iter->length() ;
                }
                packet_len = FID_LEN/*FID to pub*/+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN/*the previous segments are RVnotification header*/+\
                sizeof(type)/*type*/+sizeof(numberOfIDs)/*numberofID*/+numberOfIDs*sizeof(IDLength)/*number of fragment*/+\
                total_ID_length/*IDs*/+FID_LEN/*for data push*/ ;
                packet = Packet::make(packet_len) ;
                memcpy(packet->data(), FID._data, FID_LEN) ;
                memcpy(packet->data()+FID_LEN, &idno, sizeof(idno)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno), &iidlen, sizeof(iidlen)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen), notificationIID.c_str(), iidlen*PURSUIT_ID_LEN) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN, &type, sizeof(type)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+sizeof(type),\
                       &numberOfIDs, sizeof(numberOfIDs)) ;
                for( vec_str_iter = IDs.begin() ; vec_str_iter != IDs.end() ;vec_str_iter++)//ID length ID
                {
                    IDLength = vec_str_iter->length()/PURSUIT_ID_LEN ;
                    memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+\
                           sizeof(type)+sizeof(numberOfIDs)+IDindex, &IDLength, sizeof(IDLength)) ;
                    memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+\
                           sizeof(type)+sizeof(numberOfIDs)+IDindex+sizeof(IDLength), vec_str_iter->c_str(),\
                           vec_str_iter->length()) ;
                    IDindex += sizeof(IDLength)+vec_str_iter->length() ;
                }
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(type)+sizeof(numberOfIDs)+IDindex,\
                       backFID._data, FID_LEN) ;
                output(2).push(packet) ;
            }
        }
        else
        {
            output(1).push(p) ;
        }
    }
    else if(port == 2)
    {
        Vector<String> IIDs ;
        int i = 0 ;
        bool cachefound = false ;
        char* data ;
        unsigned int datalen ;
        IIDs.clear() ;
        if (gc->use_mac) {
            memcpy(FID._data, p->data() + 14, FID_LEN);
        } else {
            return ;//right now only support ethernet level
        }
        memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
        for (int i = 0; i < (int) numberOfIDs; i++) {
            IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
            IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                IDLength * PURSUIT_ID_LEN));
            index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
        }
        datalen = p->length() - (14+FID_LEN+sizeof(numberOfIDs)+index) ;
        data = (char*)malloc(datalen) ;
        memcpy(data, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index, datalen) ;
        if(IDs.size() == 1 && !(IDs[0].substring(0,PURSUIT_ID_LEN-1).compare((gc->RVScope).substring(0, PURSUIT_ID_LEN-1))))
        {
            output(3).push(p) ;
        }
        else
        {
            storecache(IDs, data, datalen) ;
            output(3).push(p) ;
        }
    }
}

void CacheUnit::storecache(Vector<String>& IDs, char* data, unsigned int datalen)
{
    Vector<String>::iterator id_iter ;
    Vector<CacheEntry*>::iterator cache_iter ;
    Vector<String>::iterator local_iid_iter ;
    Vector<String> newSID ;
    bool cacheupdate = false ;
    String IID ;
    IID = IDs[0].substring(IDs[0].length()-PURSUIT_ID_LEN, PURSUIT_ID_LEN) ;
    for(id_iter = IDs.begin() ; id_iter != IDs.end() ; id_iter++)
    {
         newSID.push_back((*id_iter).substring(0, (*id_iter).length()-PURSUIT_ID_LEN)) ;
    }
    for(id_iter = newSID.begin() ; id_iter != newSID.end() ; id_iter++)
    {
        for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
        {
            if((*cache_iter)->matchSID(*id_iter))
            {
                for(local_iid_iter = (*cache_iter)->IIDs.begin() ; local_iid_iter != (*cache_iter)->IIDs.end() ;local_iid_iter++)
                {
                    if(!IID.compare(*local_iid_iter))
                    {
                        cacheupdate = true ;
                        free(data) ;
                        break ;
                    }
                }
                if(!cacheupdate)
                {
                    (*cache_iter)->IIDs.push_back(IID) ;
                    (*cache_iter)->_data.set(IID, data) ;
                    (*cache_iter)->_data_length.set(IID, datalen) ;
                    cacheupdate = true ;
                }
                (*cache_iter)->SIDs = newSID ;
                break ;
            }
        }
        if(cacheupdate)
            break ;
    }
    if(!cacheupdate)
    {
        CacheEntry* newentry = new CacheEntry(newSID, IID, data, datalen) ;
        cache.push_back(newentry) ;
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CacheUnit)
ELEMENT_REQUIRES(userlevel)
ELEMENT_PROVIDES(CacheEntry)

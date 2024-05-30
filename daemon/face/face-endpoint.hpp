/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2021,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NFD_DAEMON_FACE_FACE_ENDPOINT_HPP
#define NFD_DAEMON_FACE_FACE_ENDPOINT_HPP

#include "face.hpp"
#include <deque>
#include<set>

namespace nfd {

/** \brief Represents a face-endpoint pair in the forwarder.
 *  \sa face::Face, face::EndpointId
 */
class FaceEndpoint
{
public:
  FaceEndpoint(const Face& face, EndpointId endpoint)//非基本类型的参数传递，用const加引用，防止参数被修改
    : face(const_cast<Face&>(face))
    , endpoint(endpoint)
    ,isMalicious(false)
  {
  }
  //使用endpoint作为比较的标准，由于endpoint全部为0，可能会导致bimap插入冲突
  bool operator<(const FaceEndpoint& other) const
  {
      return face.getId() < other.face.getId(); 
  }

    bool operator=(const FaceEndpoint& other) const
  {
      return face.getId() == other.face.getId(); 
  }

public:
  Face& face;
  const EndpointId endpoint;
  bool isTarget=false;//该端口是否正在探测
  size_t nReceiveInvalidProbeData=0;//探测为假的数据包个数
  size_t nReceiveTotalProbeData=0;//探测数据包总个数
  size_t nSendTotalProbe=11;//发送总的探测包数量
  double rateofReceivetoSend=0.9;
  bool receiveEnoughProbe=false;
  bool isMalicious=false;
  bool finishProbing=false;
  std::deque<::ndn::Name> cachedContentName;
  //std::set<::ndn::Name> cachedContentName;


};

// class myCompare
// {
// public:
// 	bool operator()(const FaceEndpoint& p1, const FaceEndpoint& p2) const
// 	{
// 		return p1.face.getId() > p2.face.getId();
// 	}
// };

inline std::ostream&
operator<<(std::ostream& os, const FaceEndpoint& fe)
{
  return os << '(' << fe.face.getId() << ',' << fe.endpoint << ')';
}

} // namespace nfd

#endif // NFD_DAEMON_FACE_FACE_ENDPOINT_HPP
